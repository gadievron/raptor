"""Autonomous Web Application Security Scanner.

Runs 7 phases against a target web application:

  Phase 0  Preflight       -- reachability, auth setup, telemetry reset
  Phase 1  Authentication  -- optional; form/bearer/cookie/basic
  Phase 2  Discovery       -- robots, sitemap, common paths, JS routes, API specs, fingerprint
  Phase 3  Crawl           -- recursive HTML crawl integrated with discovery results
  Phase 4  Passive checks  -- ASVS-mapped checks that don't require auth
  Phase 5  Auth checks     -- ASVS-mapped checks that require an active session
  Phase 6  Injection       -- LLM-powered fuzzing of discovered parameters and forms
  Phase 7  Report          -- consolidate findings, write output, console summary
"""

import logging
import os
import sys
import time
from pathlib import Path

# Bootstrap: add repo root to sys.path so core.* and packages.* are importable
# when this script is launched as a subprocess by raptor.py (get_safe_env()
# strips PYTHONPATH, so we derive the root from __file__ instead).
sys.path.insert(0, str(Path(__file__).parents[2]))
from typing import Any, Dict, List, Optional

from core.json import save_json
from core.logging import get_logger
from core.run.safe_io import safe_run_mkdir
from packages.web.auth import AuthManager, AuthSession, AuthenticationError
from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.discovery import Discoverer, DiscoveryResult
from packages.web.models import WebFinding
from packages.web.checks import registry
from packages.web.checks.base import CheckResult

logger = get_logger()

_FINDING_VULN_MAP = {
    "V2":    "authn_bypass",
    "V3":    "session_management",
    "V4":    "access_control",
    "V5":    "injection",
    "V7":    "information_disclosure",
    "V9":    "insecure_transport",
    "V13":   "api_security",
    "V14.4": "missing_security_header",
    "V14.5": "cors_misconfiguration",
}


class WebScanner:
    """Fully autonomous web application security scanner."""

    def __init__(
        self,
        base_url: str,
        llm=None,
        out_dir: Optional[Path] = None,
        auth_manager: Optional[AuthManager] = None,
        verify_ssl: bool = True,
        reveal_secrets: bool = False,
        max_depth: int = 3,
        max_pages: int = 100,
        run_understand: bool = False,
        run_validate: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.llm = llm
        self.out_dir = out_dir or Path("out") / f"web_scan_{int(time.time())}"
        self.out_dir.parent.mkdir(parents=True, exist_ok=True)
        safe_run_mkdir(self.out_dir)
        self.auth_manager = auth_manager
        self.max_depth = max_depth
        self.max_pages = max_pages

        self.client = WebClient(
            base_url,
            verify_ssl=verify_ssl,
            reveal_secrets=reveal_secrets,
        )
        self.crawler = WebCrawler(self.client, max_depth=max_depth, max_pages=max_pages)
        from packages.web.fuzzer import WebFuzzer
        self.fuzzer = WebFuzzer(self.client, llm)
        self.run_understand = run_understand
        self.run_validate = run_validate
        self.session: Optional[AuthSession] = None
        self._phases_completed: List[str] = []
        self._finding_counter = 0

        logger.info(f"WebScanner initialised for {base_url}")

    def scan(self) -> Dict[str, Any]:
        logger.info("=" * 60)
        logger.info(f"RAPTOR WEB SCAN STARTED: {self.base_url}")
        logger.info("=" * 60)

        all_findings: List[WebFinding] = []

        if not self._phase_preflight():
            return self._empty_result("Preflight failed -- target unreachable")

        self._phase_auth()
        discovery = self._phase_discovery()
        crawl_data = self._phase_crawl(discovery)
        all_findings.extend(self._phase_passive_checks(discovery, crawl_data))

        if self.session and self.session.authenticated:
            all_findings.extend(self._phase_auth_checks(discovery, crawl_data))

        # Optional: /understand pre-analysis
        context_map = None
        if self.run_understand:
            context_map = self._phase_understand(crawl_data, discovery)

        all_findings.extend(self._phase_injection(crawl_data, context_map=context_map))

        # Optional: /validate post-analysis on needs_review findings
        if self.run_validate:
            all_findings = self._phase_validate(all_findings)

        return self._phase_report(all_findings, discovery, crawl_data)

    def _phase_preflight(self) -> bool:
        logger.info("Phase 0: Preflight")
        try:
            from core.security.prompt_telemetry import defense_telemetry
            defense_telemetry.reset()
        except Exception:
            pass
        try:
            resp = self.client.get("/")
            logger.info(f"Target reachable: HTTP {resp.status_code} ({len(resp.content)} bytes)")
            self._phases_completed.append("preflight")
            return True
        except Exception as e:
            logger.error(f"Preflight failed: {e}")
            return False

    def _phase_auth(self) -> None:
        if not self.auth_manager:
            logger.info("Phase 1: Authentication -- skipped (unauthenticated scan)")
            return
        logger.info("Phase 1: Authentication")
        try:
            self.session = self.auth_manager.authenticate(self.client)
            logger.info(f"Authentication succeeded (mode: {self.session.mode})")
            self._phases_completed.append("authentication")
        except AuthenticationError as e:
            logger.warning(f"Authentication failed -- continuing as unauthenticated: {e}")
            self.session = None

    def _phase_discovery(self) -> DiscoveryResult:
        logger.info("Phase 2: Discovery")
        result = Discoverer(self.client).discover(self.base_url)
        save_json(self.out_dir / "discovery.json", {
            "stats": result.stats(),
            "urls": result.urls[:200],
            "fingerprint": result.fingerprint,
            "common_paths_found": result.common_paths_found,
            "robots_disallow": result.robots_disallow,
            "has_openapi": result.openapi_spec is not None,
            "has_graphql": result.graphql_schema is not None,
        })
        logger.info(f"Discovery stats: {result.stats()}")
        self._phases_completed.append("discovery")
        return result

    def _phase_crawl(self, discovery: DiscoveryResult) -> Dict:
        logger.info("Phase 3: Crawl")
        for url in discovery.urls[:50]:
            self.crawler.discovered_urls.add(url)
        crawl_results = self.crawler.crawl(self.base_url)
        save_json(self.out_dir / "crawl_results.json", crawl_results)
        logger.info(f"Crawl stats: {crawl_results.get('stats', {})}")
        self._phases_completed.append("crawl")
        return crawl_results

    def _phase_passive_checks(self, discovery: DiscoveryResult, crawl_data: dict = None) -> List[WebFinding]:
        logger.info("Phase 4: Passive security checks (unauthenticated)")
        findings = []
        check_classes = registry.unauthenticated()
        logger.info(f"Running {len(check_classes)} unauthenticated checks")

        # Merge crawl data so checks can see parameters and URLs found during crawl
        discovery_ctx = dict(discovery.__dict__)
        if crawl_data:
            crawl_params = crawl_data.get("discovered_parameters", [])
            crawl_urls = crawl_data.get("visited_urls", [])
            crawl_forms = crawl_data.get("discovered_forms", [])
            discovery_ctx["parameters"] = list(set(
                discovery_ctx.get("parameters", []) + crawl_params
            ))
            discovery_ctx["urls"] = list(set(
                discovery_ctx.get("urls", []) + crawl_urls
            ))
            discovery_ctx["forms"] = (
                discovery_ctx.get("forms", []) + crawl_forms
            )

        for cls in check_classes:
            try:
                results = cls(llm=self.llm).run(
                    self.client, self.base_url, session=None, discovery=discovery_ctx,
                )
                for r in results:
                    if not r.passed:
                        findings.append(self._to_finding(r, "unauthenticated"))
            except Exception as e:
                logger.debug(f"Check {cls.__name__} failed: {e}")
        logger.info(f"Phase 4 complete: {len(findings)} findings")
        self._phases_completed.append("passive_checks")
        return findings

    def _phase_auth_checks(self, discovery: DiscoveryResult, crawl_data: dict = None) -> List[WebFinding]:
        logger.info("Phase 5: Authenticated checks")
        if not self.session:
            return []
        if self.auth_manager and not self.auth_manager.verify(self.client, self.session):
            logger.warning("Session expired before authenticated checks -- skipping")
            return []
        findings = []
        check_classes = registry.authenticated()
        logger.info(f"Running {len(check_classes)} authenticated checks")

        discovery_ctx = dict(discovery.__dict__)
        if crawl_data:
            crawl_params = crawl_data.get("discovered_parameters", [])
            crawl_urls = crawl_data.get("visited_urls", [])
            discovery_ctx["parameters"] = list(set(
                discovery_ctx.get("parameters", []) + crawl_params
            ))
            discovery_ctx["urls"] = list(set(
                discovery_ctx.get("urls", []) + crawl_urls
            ))

        for cls in check_classes:
            try:
                results = cls(llm=self.llm).run(
                    self.client, self.base_url, session=self.session, discovery=discovery_ctx,
                )
                for r in results:
                    if not r.passed:
                        findings.append(self._to_finding(r, "authenticated"))
            except Exception as e:
                logger.debug(f"Auth check {cls.__name__} failed: {e}")
        logger.info(f"Phase 5 complete: {len(findings)} findings")
        self._phases_completed.append("auth_checks")
        return findings

    def _phase_injection(
        self,
        crawl_data: Dict,
        context_map: Optional[dict] = None,
    ) -> List[WebFinding]:
        logger.info("Phase 6: Injection and fuzzing")
        fuzzer = self.fuzzer
        if not self.llm:
            logger.info("Phase 6: Running static fallback payloads -- no LLM available")
        auth_ctx = "authenticated" if self.session else "unauthenticated"
        vuln_types = ["sqli", "xss", "ssti", "command_injection", "path_traversal"]

        # Collect raw hits keyed by (endpoint_url, vuln_type) so multiple
        # vulnerable parameters on the same endpoint collapse into one finding.
        # Value: {"params": [name, ...], "payloads": [payload, ...], "example_url": str}
        grouped: Dict[tuple, dict] = {}

        def _record(endpoint: str, param: str, raw: dict) -> None:
            vuln_type = raw.get("vulnerability_type", "injection")
            key = (endpoint, vuln_type)
            if key not in grouped:
                grouped[key] = {
                    "vuln_type": vuln_type,
                    "endpoint": endpoint,
                    "params": [],
                    "payloads": [],
                }
            grouped[key]["params"].append(param)
            grouped[key]["payloads"].append(raw.get("payload", "")[:200])

        target_urls = list(dict.fromkeys(
            crawl_data.get("discovered_urls")
            or crawl_data.get("visited_urls")
            or [self.base_url]
        ))
        if self.base_url not in target_urls:
            target_urls.insert(0, self.base_url)

        params = self._prioritise_parameters(
            crawl_data.get("discovered_parameters", []),
            context_map=context_map,
        )[:20]

        # URL parameters. Test each discovered endpoint, not just the root URL.
        for target_url in target_urls[:20]:
            for param in params:
                for raw in fuzzer.fuzz_parameter(
                    target_url, param, vulnerability_types=vuln_types
                ):
                    _record(raw.get("url", target_url), param, raw)

        # Form fields
        for form in crawl_data.get("discovered_forms", [])[:10]:
            endpoint = form.get("action", self.base_url)
            method = form.get("method", "GET")
            for field_name, field_info in form.get("inputs", {}).items():
                if field_info.get("type") in ("hidden", "submit", "button"):
                    continue
                for raw in fuzzer.fuzz_parameter(
                    endpoint, field_name, vulnerability_types=["sqli", "xss"], method=method
                ):
                    _record(endpoint, field_name, raw)

        # Convert grouped hits to one WebFinding per (endpoint, vuln_type)
        findings = []
        for (endpoint, vuln_type), hit in grouped.items():
            params = hit["params"]
            payloads = hit["payloads"]
            param_list = ", ".join(f"'{p}'" for p in params)
            self._finding_counter += 1
            findings.append(WebFinding(
                id=f"WEB-{self._finding_counter:04d}",
                title=f"{vuln_type.replace('_',' ').title()} -- {len(params)} parameter(s) affected",
                severity="high", confidence="medium", status="needs_review",
                url=endpoint,
                evidence=(
                    f"Affected parameters: {param_list}\n"
                    f"Example payload: {payloads[0]}"
                ),
                description=(
                    f"{len(params)} parameter(s) on this endpoint may be vulnerable to "
                    f"{vuln_type.replace('_', ' ')}: {param_list}."
                ),
                recommendation=(
                    "Validate and sanitise all user-supplied input server-side. "
                    "Use parameterised queries for database access, "
                    "context-appropriate output encoding for XSS, "
                    "and allowlists for file/command parameters."
                ),
                vuln_type="injection", asvs_category="V5", check_id="V5.2.1",
                auth_context=auth_ctx,
            ))

        logger.info(f"Phase 6 complete: {len(findings)} injection findings ({sum(len(h['params']) for h in grouped.values())} total hits grouped)")
        self._phases_completed.append("injection")
        return findings


    def _phase_understand(self, crawl_data: dict, discovery: DiscoveryResult) -> Optional[dict]:
        """Build a URL-native context map for the discovered web attack surface."""
        logger.info("Phase 6a: Building web context map")
        context_map = self._build_web_context_map(crawl_data, discovery)
        save_json(self.out_dir / "context-map.json", context_map)
        save_json(self.out_dir / "web-context-map.json", context_map)
        self._phases_completed.append("understand")
        return context_map

    def _phase_validate(self, findings: List[WebFinding]) -> List[WebFinding]:
        """Optional Phase 7a: run /validate on needs_review findings.

        Pipes injection/fuzzing findings through the validation pipeline
        to promote them to confirmed or ruled_out, reducing false positives.
        """
        needs_review = [f for f in findings if f.status == "needs_review"]
        if not needs_review:
            return findings

        try:
            from core.security.rule_of_two import is_interactive
            if not is_interactive():
                logger.info("Phase 7a: /validate skipped -- non-interactive mode (Rule of Two)")
                return findings
        except ImportError:
            return findings

        logger.info(f"Phase 7a: Validating {len(needs_review)} needs_review findings")
        try:
            import shutil
            from pathlib import Path

            # Write needs_review findings to a temp file for validation pipeline
            findings_for_validate = [
                self._web_finding_to_agentic_result(f) for f in needs_review
            ]
            findings_input = self.out_dir / "web_findings_for_validation.json"
            save_json(findings_input, {"results": findings_for_validate})

            claude_bin = shutil.which("claude")
            if not claude_bin:
                logger.info("Phase 7a: claude not on PATH -- skipping /validate")
                return findings

            from core.orchestration.agentic_passes import run_validate_postpass
            result = run_validate_postpass(
                target=Path(self.base_url),
                agentic_out_dir=self.out_dir,
                analysis_report=findings_input,
                claude_bin=claude_bin,
            )
            if result.ran:
                logger.info("Phase 7a: /validate complete")
                self._phases_completed.append("validate")
        except Exception as e:
            logger.debug(f"Phase 7a: /validate failed: {e}")

        return findings

    def _build_web_context_map(self, crawl_data: dict, discovery: DiscoveryResult) -> dict:
        urls = list(dict.fromkeys(
            crawl_data.get("discovered_urls")
            or crawl_data.get("visited_urls")
            or discovery.urls
            or [self.base_url]
        ))
        forms = crawl_data.get("discovered_forms", [])
        parameters = crawl_data.get("discovered_parameters", [])

        entry_points = [{"type": "url", "url": url} for url in urls[:100]]
        entry_points.extend({
            "type": "form",
            "url": form.get("action", self.base_url),
            "method": form.get("method", "GET"),
            "fields": list((form.get("inputs") or {}).keys()),
        } for form in forms[:50])

        sinks = []
        for param in parameters:
            lower = str(param).lower()
            if any(token in lower for token in ("id", "query", "q", "search", "filter")):
                sinks.append({"type": "injection_candidate", "parameter": param})
            if any(token in lower for token in ("url", "uri", "path", "file", "next", "redirect")):
                sinks.append({"type": "ssrf_or_redirect_candidate", "parameter": param})

        context_map = {
            "target": self.base_url,
            "kind": "web_application",
            "entry_points": entry_points,
            "sources": [{"type": "http_parameter", "name": p} for p in parameters],
            "sinks": sinks,
            "trust_boundaries": [
                {"name": "browser_to_server", "source": "client", "destination": "web_app"},
                {"name": "unauthenticated_to_authenticated", "source": "anonymous", "destination": "session"},
            ],
            "metadata": {
                "fingerprint": discovery.fingerprint,
                "stats": discovery.stats(),
                "forms": len(forms),
                "parameters": len(parameters),
            },
        }
        return context_map

    def _prioritise_parameters(
        self,
        parameters: List[str],
        context_map: Optional[dict] = None,
    ) -> List[str]:
        if not context_map:
            return list(parameters)

        sink_params = []
        for sink in context_map.get("sinks", []):
            param = sink.get("parameter")
            if param:
                sink_params.append(param)

        ordered = []
        for param in sink_params + list(parameters):
            if param not in ordered:
                ordered.append(param)
        return ordered

    def _web_finding_to_agentic_result(self, finding: WebFinding) -> Dict[str, Any]:
        data = finding.to_dict()
        return {
            "id": data.get("id"),
            "title": data.get("title"),
            "vuln_type": data.get("vuln_type"),
            "confidence": data.get("confidence", "medium"),
            "severity": data.get("severity"),
            "is_exploitable": data.get("status") == "needs_review",
            "exploitable": data.get("status") == "needs_review",
            "file": data.get("url"),
            "line": 1,
            "url": data.get("url"),
            "evidence": data.get("evidence"),
            "description": data.get("description"),
            "recommendation": data.get("recommendation"),
        }

    def _phase_report(self, findings, discovery, crawl_data) -> Dict[str, Any]:
        logger.info("Phase 7: Report")
        findings_dicts = [f.to_dict() for f in findings]
        save_json(self.out_dir / "web_findings.json", {"findings": findings_dicts})
        try:
            from core.security.prompt_telemetry import defense_telemetry
            defense_telemetry.write_summary(self.out_dir)
        except Exception:
            pass
        self._phases_completed.append("report")

        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        result = {
            "target": self.base_url,
            "findings": findings_dicts,
            "total_findings": len(findings),
            "total_vulnerabilities": len(findings),
            "auth_context": "authenticated" if (self.session and self.session.authenticated) else "unauthenticated",
            "discovery": discovery.stats(),
            "crawl": crawl_data.get("stats", {}),
            "findings_by_severity": by_sev,
            "phases_completed": self._phases_completed,
        }
        save_json(self.out_dir / "web_scan_report.json", result)
        logger.info(f"Scan complete. {len(findings)} findings. Report: {self.out_dir}")
        return result

    def _to_finding(self, result: CheckResult, auth_context: str) -> WebFinding:
        self._finding_counter += 1
        return WebFinding(
            id=f"WEB-{self._finding_counter:04d}",
            title=result.check_name,
            severity=result.severity,
            confidence=result.confidence,
            status="confirmed",
            url=result.url,
            evidence=result.evidence,
            description=result.detail,
            recommendation=result.recommendation,
            vuln_type=_FINDING_VULN_MAP.get(result.category.value, "other"),
            asvs_category=result.category.value,
            check_id=result.check_id,
            auth_context=auth_context,
        )

    def _empty_result(self, reason: str) -> Dict[str, Any]:
        return {
            "target": self.base_url, "findings": [], "total_findings": 0,
            "total_vulnerabilities": 0, "auth_context": "unauthenticated",
            "discovery": {}, "crawl": {}, "findings_by_severity": {},
            "phases_completed": self._phases_completed, "error": reason,
        }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication modes:
  none    Unauthenticated scan (default)
  form    HTML form login  (--login-url, --username, --password)
  bearer  JWT/token        (--token)
  cookie  Browser export   (--cookies "name=val; name2=val2")
  basic   HTTP Basic auth  (--username, --password)

For MFA/SSO apps: use 'cookie' (log in manually, export cookies) or
'bearer' (get token from your auth flow, pass it directly).

Examples:
  python3 scanner.py --url https://app.example.com
  python3 scanner.py --url https://app.example.com --auth-mode form \\
      --login-url /login --username admin --password secret
  python3 scanner.py --url https://app.example.com --auth-mode cookie \\
      --cookies "session=abc123; csrftoken=xyz"
  python3 scanner.py --url https://api.example.com --auth-mode bearer \\
      --token "eyJhbGci..."
""",
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--out")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--reveal-secrets", action="store_true")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM payload generation and use static fallback payloads",
    )

    ag = parser.add_argument_group("authentication")
    ag.add_argument("--auth-mode", default="none",
                    choices=["none", "form", "bearer", "cookie", "basic"])
    ag.add_argument("--login-url")
    ag.add_argument("--logout-url")
    ag.add_argument("--username")
    ag.add_argument("--password")
    ag.add_argument("--token")
    ag.add_argument("--cookies")
    ag.add_argument("--username-field", default="username")
    ag.add_argument("--password-field", default="password")

    adv = parser.add_argument_group("advanced pipeline")
    adv.add_argument(
        "--understand", action="store_true",
        help="Run /understand --map before injection phase to build adversarial context map",
    )
    adv.add_argument(
        "--validate", action="store_true",
        help="Run /validate on needs_review findings after fuzzing to confirm exploitability",
    )

    args = parser.parse_args()

    out_dir = Path(args.out) if args.out else None
    if not out_dir:
        from core.config import RaptorConfig
        out_dir = RaptorConfig.get_out_dir() / f"web_scan_{int(time.time())}"

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

    auth_manager = None
    if args.auth_mode != "none":
        from packages.web.auth import make_auth_manager
        try:
            auth_manager = make_auth_manager(
                args.auth_mode,
                username=args.username, password=args.password,
                token=args.token, cookies=args.cookies,
                login_url=args.login_url, logout_url=args.logout_url,
                username_field=args.username_field, password_field=args.password_field,
            )
        except ValueError as e:
            print(f"Error: {e}")
            return 1

    if args.no_llm:
        llm = None
    else:
        from packages.llm_analysis import get_client
        llm = get_client()

    print("\n" + "=" * 70)
    print("RAPTOR WEB APPLICATION SECURITY SCANNER")
    print("=" * 70)
    print(f"Target:    {args.url}")
    print(f"Auth mode: {args.auth_mode}")
    print(f"Output:    {out_dir}")
    print(f"LLM:       {'enabled' if llm else 'disabled'}")
    print("=" * 70 + "\n")

    scanner = WebScanner(
        base_url=args.url, llm=llm, out_dir=out_dir,
        auth_manager=auth_manager, verify_ssl=not args.insecure,
        reveal_secrets=args.reveal_secrets,
        max_depth=args.max_depth, max_pages=args.max_pages,
        run_understand=args.understand,
        run_validate=args.validate,
    )

    try:
        results = scanner.scan()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130
    except Exception as e:
        print(f"\nScan failed: {e}")
        logger.error("Scan failed", exc_info=True)
        return 1

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"Auth:           {results['auth_context']}")
    print(f"Pages crawled:  {results['crawl'].get('total_pages', 0)}")
    print(f"URLs found:     {results['discovery'].get('total_urls', 0)}")
    print(f"Total findings: {results['total_findings']}")
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = results.get("findings_by_severity", {}).get(sev, 0)
        if n:
            print(f"  {sev.capitalize()}: {n}")
    print(f"\nOutput: {out_dir}")
    print("=" * 70 + "\n")
    return 1 if results.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
