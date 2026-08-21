#!/usr/bin/env python3
"""
Autonomous Web Security Scanner

Combines crawling, fuzzing, and LLM analysis for complete web app testing.
"""

import os
import sys
from pathlib import Path
from typing import Any, Self

if __name__ == "__main__":
    # Direct script invocation only — module imports rely on the
    # caller's sys.path. Hard lookup per the path-safety rule
    # (CLAUDE.md): RAPTOR_DIR is the only permitted sys.path
    # addition, and a missing value must KeyError loudly rather than
    # fall back to a positional walk.
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.json import save_json
from core.llm.providers import LLMProvider
from core.logging import get_logger
from core.run.safe_io import safe_run_mkdir
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.ffuf import FfufConfig, FfufRunner
from packages.web.fuzzer import WebFuzzer

logger = get_logger()


class WebScanner:
    """Fully autonomous web application security scanner."""

    def __init__(
        self,
        base_url: str,
        llm: LLMProvider | None,
        out_dir: Path,
        verify_ssl: bool = True,
        reveal_secrets: bool = False,
        max_depth: int = 3,
        max_pages: int = 100,
        ffuf_config: FfufConfig | None = None,
        block_private_ips: bool = True,
        verify_findings: bool = True,
        max_verifications: int = 25,
    ):
        self.base_url = base_url
        self.llm = llm
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.ffuf_config = ffuf_config
        self.verify_findings = verify_findings
        self.max_verifications = max_verifications
        self.reveal_secrets = reveal_secrets

        # Initialize components
        self.client = WebClient(
            base_url, verify_ssl=verify_ssl, reveal_secrets=reveal_secrets,
            block_private_ips=block_private_ips,
        )
        self.crawler = WebCrawler(self.client, max_depth=max_depth, max_pages=max_pages)
        self.fuzzer = WebFuzzer(self.client, llm) if llm else None
        self.ffuf = FfufRunner(base_url, out_dir, reveal_secrets=reveal_secrets) if ffuf_config else None

        logger.info(
            f"Web scanner initialized for {base_url} "
            f"(verify_ssl={verify_ssl}, max_depth={max_depth}, max_pages={max_pages})"
        )

    def scan(self) -> dict[str, Any]:
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
        save_json(crawl_file, crawl_results)

        logger.info("Discovery complete: %s", crawl_results['stats'])

        # Phase 2: Intelligent Fuzzing
        fuzzing_findings = []
        probe_contexts = []

        if self.fuzzer:
            logger.info("Phase 2: Intelligent Fuzzing")
            # Fuzz each parameter only at the URLs where the crawler
            # actually discovered it. Pre-fix this was a full
            # URL × parameter cross-product — every discovered
            # parameter probed against every discovered URL, each
            # cell paying LLM payload generation plus probe requests
            # even for endpoints that never take the parameter. The
            # crawler's `parameter_urls` mapping scopes the loop;
            # form input names keep their own dedicated loop below
            # (they are fuzzed against their form action, not query
            # strings).
            discovered_params = crawl_results['discovered_parameters']
            target_urls = sorted(self.crawler.discovered_urls) or [self.base_url]
            param_urls = getattr(self.crawler, "parameter_urls", None)
            if not isinstance(param_urls, dict):
                param_urls = {}
            if param_urls:
                fuzz_cells = [
                    (url, param)
                    for param in sorted(param_urls)
                    for url in sorted(param_urls[param])
                ]
            else:
                # No mapping (legacy crawler double, or parameters
                # discovered without URL context) — fall back to the
                # cross-product rather than silently skipping.
                fuzz_cells = [
                    (url, param)
                    for url in target_urls
                    for param in discovered_params
                ]
            full_product = len(target_urls) * len(discovered_params)
            if full_product > len(fuzz_cells):
                logger.info(
                    "Phase 2: fuzzing %d URL x parameter pair(s); "
                    "param-to-URL mapping pruned %d of %d "
                    "cross-product cells",
                    len(fuzz_cells), full_product - len(fuzz_cells),
                    full_product,
                )
            for target_url, param in fuzz_cells:
                findings = self.fuzzer.fuzz_parameter(
                    target_url,
                    param,
                    vulnerability_types=['sqli', 'xss', 'command_injection']
                )
                fuzzing_findings.extend(findings)

            for form in self.crawler.discovered_forms:
                method = form.get("method", "GET").upper()
                action = form.get("action", "")
                if not action:
                    continue
                for param_name, param_info in form.get("inputs", {}).items():
                    findings = self.fuzzer.fuzz_parameter(
                        action,
                        param_name,
                        param_type=param_info.get("type", "text"),
                        vulnerability_types=['sqli', 'xss', 'command_injection'],
                        method=method,
                    )
                    fuzzing_findings.extend(findings)
                    probe_contexts.extend(
                        (f, action, param_name, method) for f in findings
                    )

            # Surface the memoisation win so operators can see the
            # redundant-probe reduction in the run log. Defensive
            # against fuzzer doubles without the stats property.
            try:
                cache_hits, cache_keys = self.fuzzer.payload_cache_stats
            except (TypeError, ValueError, AttributeError):
                cache_hits, cache_keys = 0, 0
            if cache_hits:
                logger.info(
                    "Phase 2: payload generation memoised — %d LLM "
                    "call(s) saved across %d unique "
                    "(param, type, vuln) key(s)",
                    cache_hits, cache_keys,
                )
        else:
            logger.warning("Phase 2: Skipping fuzzing (no LLM available)")

        # Phase 2.5: mechanical verification of heuristic hits —
        # replay + control differentials through the same scoped,
        # rate-limited client. Findings are never dropped here;
        # verification adds an evidence tier and LabeledAttempt
        # records for raptor-verified-outcomes.
        verification_summary = None
        if self.verify_findings and probe_contexts:
            verification_summary = self._verify_findings(probe_contexts)

        # Optional Phase 2b: explicit ffuf content discovery.
        ffuf_results = None
        if self.ffuf and self.ffuf_config:
            logger.info("Phase 2b: ffuf content discovery")
            ffuf_results = self.ffuf.run(self.ffuf_config)

        # Phase 3: Generate Report
        logger.info("Phase 3: Generating Security Report")
        report = {
            'target': self.base_url,
            'discovery': crawl_results['stats'],
            'findings': fuzzing_findings,
            'total_vulnerabilities': len(fuzzing_findings),
        }
        if verification_summary is not None:
            report['verification'] = verification_summary
        if ffuf_results is not None:
            report['ffuf'] = ffuf_results

        # Save report
        report_file = self.out_dir / "web_scan_report.json"
        save_json(report_file, report)

        logger.info("Web scan complete. Found %d potential vulnerabilities", len(fuzzing_findings))
        logger.info("Report saved to %s", report_file)

        return report

    def _verify_findings(self, probe_contexts: list) -> dict[str, Any]:
        """Phase 2.5 — replay/control verification of heuristic hits.

        Annotates each finding dict in place with a ``verification``
        block, writes LabeledAttempt records for the run, and returns
        the summary for the report. Soft by design: nothing is
        dropped, and any per-finding failure degrades to
        ``inconclusive``.
        """
        from packages.web.attempts import build_web_attempt, write_web_attempts
        from packages.web.oracle import VerificationOracle

        logger.info(
            "Phase 2.5: Verifying %d heuristic finding(s) (cap %d)",
            len(probe_contexts), self.max_verifications,
        )
        oracle = VerificationOracle(self.client)
        counts = {"verified": 0, "refuted": 0, "inconclusive": 0, "skipped": 0}
        attempts = []

        for i, (finding, url, param, method) in enumerate(probe_contexts):
            if i >= self.max_verifications:
                finding['verification'] = {
                    'status': 'skipped',
                    'reason': 'per-run verification cap reached',
                }
                counts["skipped"] += 1
                continue
            result = oracle.verify(
                url, param, finding.get('payload', ''),
                finding.get('vulnerability_type', ''), method,
            )
            finding['verification'] = {
                'status': result.status,
                'evidence_type': result.evidence_type,
                'reason': result.reason,
                'requests_used': result.requests_used,
            }
            counts[result.status] = counts.get(result.status, 0) + 1
            try:
                attempts.append(build_web_attempt(
                    url=url, param=param,
                    payload=finding.get('payload', ''),
                    vuln_type=finding.get('vulnerability_type', ''),
                    method=method, result=result,
                    reveal_secrets=self.reveal_secrets,
                ))
            except Exception:
                logger.debug("labeled-attempt build failed", exc_info=True)

        written = write_web_attempts(attempts, self.out_dir)
        summary = dict(counts)
        summary["requests_used"] = oracle.requests_used
        summary["transport_errors"] = oracle.errors
        summary["records_written"] = len(written)
        if oracle.errors:
            # Loud: an unreachable/flaky target means verification is
            # partial — the operator must not read heuristic findings
            # as oracle-checked.
            logger.warning(
                "Verification degraded: %d transport error(s); "
                "%d finding(s) remain inconclusive/heuristic-tier",
                oracle.errors, counts["inconclusive"],
            )
        logger.info(
            "Verification: %d verified, %d refuted, %d inconclusive, "
            "%d skipped (%d requests)",
            counts["verified"], counts["refuted"],
            counts["inconclusive"], counts["skipped"],
            oracle.requests_used,
        )
        return summary

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def build_arg_parser():
    """Build the CLI parser for the web scanner."""
    import argparse

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
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL/TLS certificate verification (INSECURE but you know what you are doing, right?)")
    parser.add_argument(
        "--ffuf-wordlist",
        type=Path,
        help="Opt-in ffuf content discovery wordlist. ffuf is only run when this is set.",
    )
    parser.add_argument(
        "--ffuf-path",
        default="FUZZ",
        help="In-scope ffuf URL path/template containing FUZZ (default: FUZZ)",
    )
    parser.add_argument("--ffuf-bin", default="ffuf", help="ffuf binary name/path (default: ffuf)")
    parser.add_argument("--ffuf-threads", type=int, default=10, help="ffuf worker threads (default: 10)")
    parser.add_argument("--ffuf-rate", type=int, help="Optional ffuf request rate limit")
    parser.add_argument("--ffuf-timeout", type=int, default=30, help="ffuf per-request timeout in seconds (default: 30)")
    parser.add_argument(
        "--ffuf-report-limit",
        type=int,
        default=50,
        help="Maximum ffuf matches to copy into web_scan_report.json; raw JSON is always kept (default: 50)",
    )
    parser.add_argument(
        "--ffuf-max-runtime",
        type=int,
        default=300,
        help="Maximum sandboxed ffuf runtime in seconds (default: 300)",
    )
    parser.add_argument(
        "--ffuf-no-auto-calibration",
        action="store_true",
        help="Disable ffuf auto-calibration (-ac is enabled by default)",
    )
    parser.add_argument(
        "--ffuf-match-status",
        default="200,204,301,302,307,401,403,405,500",
        help="ffuf match status codes for -mc; pass an empty string to omit -mc",
    )
    parser.add_argument(
        "--ffuf-filter-status",
        default="404",
        help="ffuf filter status codes for -fc; pass an empty string to omit -fc",
    )
    parser.add_argument(
        "--ffuf-filter-size",
        type=int,
        help="Optional ffuf response size filter for -fs",
    )
    parser.add_argument(
        "--ffuf-header",
        action="append",
        default=[],
        help="Header to pass to ffuf; repeatable, e.g. --ffuf-header 'Header-Name: value'",
    )
    parser.add_argument(
        "--ffuf-cookie",
        action="append",
        default=[],
        help="Cookie to pass to ffuf; repeatable, e.g. --ffuf-cookie 'session=...'",
    )
    parser.add_argument(
        "--reveal-secrets",
        action="store_true",
        help="Preserve secrets in web artifacts for local debugging; defaults to redaction",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the replay/control verification pass on heuristic findings",
    )
    parser.add_argument(
        "--max-verifications",
        type=int,
        default=25,
        help="Maximum findings to verify per run; the rest are marked skipped (default: 25)",
    )
    return parser


def build_ffuf_config(args) -> FfufConfig | None:
    """Convert parsed CLI args into an optional ffuf configuration."""
    if not args.ffuf_wordlist:
        return None
    return FfufConfig(
        wordlist=args.ffuf_wordlist,
        path_template=args.ffuf_path,
        threads=args.ffuf_threads,
        rate=args.ffuf_rate,
        timeout=args.ffuf_timeout,
        max_runtime=args.ffuf_max_runtime,
        report_limit=args.ffuf_report_limit,
        binary=args.ffuf_bin,
        auto_calibration=not args.ffuf_no_auto_calibration,
        match_status=args.ffuf_match_status or None,
        filter_status=args.ffuf_filter_status or None,
        filter_size=args.ffuf_filter_size,
        headers=tuple(args.ffuf_header or ()),
        cookies=tuple(args.ffuf_cookie or ()),
    )


def main():
    """CLI entry point for web scanner."""
    import time

    from core.config import RaptorConfig

    parser = build_arg_parser()
    args = parser.parse_args()
    ffuf_config = build_ffuf_config(args)

    # Determine output directory
    if args.out:
        out_dir = Path(args.out)
    else:
        timestamp = int(time.time())
        out_dir = RaptorConfig.get_out_dir() / f"web_scan_{timestamp}"

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

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
    logger.info("Target: %s", args.url)
    logger.info("Output: %s", out_dir)

    # Initialize LLM client with multi-model support, fallback, and retry
    from core.llm.factory import get_client
    llm = get_client()
    if llm:
        logger.info("LLM client initialized")
    else:
        print("\n⚠️  Warning: Could not initialize LLM client", file=sys.stderr)
        print("    Web scanning will work but fuzzing will be limited", file=sys.stderr)

    # Run scan
    verify_ssl = not args.insecure

    scanner = WebScanner(
        args.url,
        llm,
        out_dir,
        verify_ssl=verify_ssl,
        reveal_secrets=bool(args.reveal_secrets),
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        ffuf_config=ffuf_config,
        verify_findings=not args.no_verify,
        max_verifications=args.max_verifications,
    )

    try:
        results = scanner.scan()

        print("\n" + "=" * 70)
        print("Scan Complete")
        print("=" * 70)
        print(f"✓ Pages crawled: {results['discovery'].get('total_pages', 0)}")
        print(f"✓ Parameters found: {results['discovery'].get('total_parameters', 0)}")
        print(f"✓ Vulnerabilities found: {results['total_vulnerabilities']}")
        verification = results.get('verification')
        if verification:
            print(
                f"✓ Oracle verification: {verification['verified']} verified, "
                f"{verification['refuted']} refuted, "
                f"{verification['inconclusive']} inconclusive, "
                f"{verification['skipped']} skipped"
            )
        print(f"\n📁 Results saved to: {out_dir}")
        print(f"   - Crawl results: {out_dir}/crawl_results.json")
        print(f"   - Security report: {out_dir}/web_scan_report.json")
        print("=" * 70 + "\n")

        logger.info("=" * 70)
        logger.info("WEB SCAN COMPLETE")
        logger.info("=" * 70)
        logger.info("Vulnerabilities found: %s", results['total_vulnerabilities'])

        # A completed scan is a success regardless of how many vulnerabilities
        # it found — the findings live in web_scan_report.json. The raptor.py
        # lifecycle wrapper treats any non-zero exit as a failed run, so
        # exiting 1 on findings would record every successful vuln-finding
        # scan as status=failed.
        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user", file=sys.stderr)
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n✗ Scan failed: {e}", file=sys.stderr)
        logger.exception("Scan failed")
        return 1
    finally:
        scanner.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SandboxSetupError as e:
        print(
            f"\nRAPTOR: web scan aborted — sandbox isolation could not engage.\n{e}",
            file=sys.stderr,
        )
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
