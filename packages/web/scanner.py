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
from urllib.parse import parse_qsl, urlparse

# Bootstrap: add repo root to sys.path so core.* and packages.* are importable
# when this script is launched as a subprocess by raptor.py (get_safe_env()
# strips PYTHONPATH, so we derive the root from __file__ instead).
sys.path.insert(0, str(Path(__file__).parents[2]))
from typing import Any, Dict, List, Optional

from core.context_guard import build_web_context_guard_report
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
from packages.web.research_landscape import (
    assess_research_landscape,
    high_priority_theme_ids,
)
from packages.web.session_context import build_web_session_context
from packages.web.verified_outcomes import verified_outcomes_for_findings

logger = get_logger()

HIGH_RISK_WEB_PARAMS = {
    "cmd", "command", "exec", "execute", "code", "input", "template",
    "host", "ip", "addr", "target", "server", "url", "uri", "path", "file",
    "next", "redirect", "redirect_uri", "return_url", "q", "query", "search",
    "filter", "id", "uuid",
}

HIGH_RISK_PATH_TOKENS = {
    "eval", "exec", "command", "cmd", "ping", "diagnostic", "template",
    "search", "redirect", "proxy", "fetch", "upload", "debug", "admin",
}


WEB_INJECTION_CWE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssti": "CWE-94",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
}

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
        max_fuzz_urls: int = 5,
        max_fuzz_params: int = 12,
        max_fuzz_forms: int = 5,
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
        self.max_fuzz_urls = max_fuzz_urls
        self.max_fuzz_params = max_fuzz_params
        self.max_fuzz_forms = max_fuzz_forms

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
        # Value carries structured proof so a future VerifiedOutcome adapter can
        # consume the finding without scraping prose from the evidence string.
        grouped: Dict[tuple, dict] = {}

        def _record(endpoint: str, param: str, raw: dict, attack_vector: str) -> None:
            vuln_type = raw.get("vulnerability_type", "injection")
            key = (endpoint, vuln_type)
            if key not in grouped:
                grouped[key] = {
                    "vuln_type": vuln_type,
                    "endpoint": endpoint,
                    "params": [],
                    "payloads": [],
                    "response_evidence": [],
                    "baseline_evidence": [],
                    "attack_evidence": [],
                    "diff_summaries": [],
                    "oracle_signals": [],
                    "status_codes": [],
                    "methods": [],
                    "attack_vectors": [],
                }
            grouped[key]["params"].append(param)
            grouped[key]["payloads"].append(raw.get("payload", "")[:200])
            if raw.get("response_evidence"):
                grouped[key]["response_evidence"].append(raw["response_evidence"])
            if raw.get("baseline_evidence"):
                grouped[key]["baseline_evidence"].append(raw["baseline_evidence"])
            if raw.get("attack_evidence"):
                grouped[key]["attack_evidence"].append(raw["attack_evidence"])
            if raw.get("diff_summary"):
                grouped[key]["diff_summaries"].append(raw["diff_summary"])
            if raw.get("oracle_signal"):
                grouped[key]["oracle_signals"].append(raw["oracle_signal"])
            if raw.get("status_code") is not None:
                grouped[key]["status_codes"].append(raw["status_code"])
            if raw.get("method"):
                grouped[key]["methods"].append(raw["method"])
            grouped[key]["attack_vectors"].append(attack_vector)

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
        )[:self.max_fuzz_params]
        target_urls = self._prioritise_urls(target_urls, params)

        # URL parameters. Test each discovered endpoint, not just the root URL.
        selected_urls = target_urls[:self.max_fuzz_urls]
        logger.info(
            f"Phase 6 budget: fuzzing {len(selected_urls)} URL(s), "
            f"{len(params)} parameter(s), "
            f"{min(len(crawl_data.get('discovered_forms', [])), self.max_fuzz_forms)} form(s)"
        )
        for target_url in selected_urls:
            url_params = self._query_parameters(target_url)
            target_params = self._prioritise_parameters(
                url_params + params,
                context_map=context_map,
            )[:self.max_fuzz_params]
            for param in target_params:
                for raw in fuzzer.fuzz_parameter(
                    target_url, param, vulnerability_types=vuln_types
                ):
                    _record(raw.get("url", target_url), param, raw, "query_param")

        # Form fields
        for form in crawl_data.get("discovered_forms", [])[:self.max_fuzz_forms]:
            endpoint = form.get("action", self.base_url)
            method = form.get("method", "GET")
            attack_vector = "request_body" if str(method).upper() == "POST" else "query_param"
            for field_name, field_info in form.get("inputs", {}).items():
                if field_info.get("type") in ("hidden", "submit", "button"):
                    continue
                for raw in fuzzer.fuzz_parameter(
                    endpoint, field_name, vulnerability_types=["sqli", "xss"], method=method
                ):
                    _record(endpoint, field_name, raw, attack_vector)

        # Convert grouped hits to one WebFinding per (endpoint, vuln_type)
        findings = []
        for (endpoint, vuln_type), hit in grouped.items():
            params = hit["params"]
            payloads = hit["payloads"]
            response_evidence = hit.get("response_evidence") or []
            baseline_evidence = hit.get("baseline_evidence") or []
            attack_evidence = hit.get("attack_evidence") or response_evidence
            diff_summaries = hit.get("diff_summaries") or []
            oracle_signals = hit.get("oracle_signals") or []
            attack_vectors = hit.get("attack_vectors") or []
            methods = hit.get("methods") or []
            param_list = ", ".join(f"'{p}'" for p in params)
            evidence_snippet = response_evidence[0] if response_evidence else ""
            diff_summary = diff_summaries[0] if diff_summaries else ""
            oracle_signal = oracle_signals[0] if oracle_signals else "web_oracle"
            self._finding_counter += 1
            findings.append(WebFinding(
                id=f"WEB-{self._finding_counter:04d}",
                title=f"{vuln_type.replace('_',' ').title()} -- {len(params)} parameter(s) affected",
                severity="high", confidence="medium", status="needs_review",
                url=endpoint,
                evidence=(
                    f"Affected parameters: {param_list}\n"
                    f"Example payload: {payloads[0]}\n"
                    f"Response evidence: {evidence_snippet}\n"
                    f"Baseline/attack diff: {diff_summary}\n"
                    f"Oracle signal: {oracle_signal}"
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
                cwe_id=WEB_INJECTION_CWE.get(vuln_type),
                confirmed=True,
                target_url=endpoint,
                confirmation_payload=payloads[0] if payloads else None,
                response_evidence=evidence_snippet,
                baseline_evidence=baseline_evidence[0] if baseline_evidence else None,
                attack_evidence=attack_evidence[0] if attack_evidence else None,
                diff_summary=diff_summary or None,
                attack_vector=attack_vectors[0] if attack_vectors else None,
                method=methods[0] if methods else None,
                reproducible=False,
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
        research_landscape = assess_research_landscape(
            discovery=discovery,
            crawl_data=crawl_data,
            registered_check_ids=(check.check_id for check in registry.all()),
        )
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
                "research_priority_themes": high_priority_theme_ids(research_landscape),
            },
            "research_landscape": research_landscape,
        }
        return context_map

    def _prioritise_parameters(
        self,
        parameters: List[str],
        context_map: Optional[dict] = None,
    ) -> List[str]:
        if not context_map:
            return self._rank_parameters(list(parameters))

        sink_params = []
        for sink in context_map.get("sinks", []):
            param = sink.get("parameter")
            if param:
                sink_params.append(param)

        ordered = []
        for param in sink_params + self._rank_parameters(list(parameters)):
            if param not in ordered:
                ordered.append(param)
        return ordered

    def _rank_parameters(self, parameters: List[str]) -> List[str]:
        indexed = list(dict.fromkeys(parameters))
        return sorted(
            indexed,
            key=lambda param: (
                self._parameter_score(param),
                -indexed.index(param),
            ),
            reverse=True,
        )

    def _parameter_score(self, param: str) -> int:
        lower = str(param).lower()
        score = 0
        if lower in HIGH_RISK_WEB_PARAMS:
            score += 100
        if any(token in lower for token in ("cmd", "command", "exec", "code")):
            score += 80
        if any(token in lower for token in ("host", "ip", "target", "url", "uri")):
            score += 60
        if any(token in lower for token in ("file", "path", "template", "redirect")):
            score += 50
        return score

    def _prioritise_urls(self, urls: List[str], parameters: List[str]) -> List[str]:
        indexed = list(dict.fromkeys(urls))
        known_params = set(parameters)
        return sorted(
            indexed,
            key=lambda url: (
                self._url_score(url, known_params),
                -indexed.index(url),
            ),
            reverse=True,
        )

    def _url_score(self, url: str, known_params: set[str]) -> int:
        parsed = urlparse(url)
        query_params = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        path_tokens = {
            token
            for token in parsed.path.lower().replace("-", "_").split("/")
            for token in token.split("_")
            if token
        }
        score = 0
        if query_params:
            score += 50
            if len(query_params) <= 3:
                score += 120
            elif len(query_params) > 5:
                score -= (len(query_params) - 5) * 100
        param_scores = sorted(
            (self._parameter_score(param) for param in query_params),
            reverse=True,
        )[:3]
        score += sum(param_scores)
        for param in query_params:
            if param in known_params:
                score += 20
        if path_tokens & HIGH_RISK_PATH_TOKENS:
            score += 40
        if parsed.path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico")):
            score -= 100
        if any(token in parsed.path.lower() for token in ("/.git", "/actuator/health")):
            score -= 30
        return score

    def _query_parameters(self, url: str) -> List[str]:
        return [
            name
            for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True)
            if name
        ]

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
        research_landscape = assess_research_landscape(
            discovery=discovery,
            crawl_data=crawl_data,
            registered_check_ids=(check.check_id for check in registry.all()),
        )
        save_json(self.out_dir / "research_landscape.json", research_landscape)

        session_context = build_web_session_context(
            base_url=self.base_url,
            discovery=discovery,
            crawl_data=crawl_data,
            client=self.client,
            session=self.session,
            findings=findings,
        )
        save_json(self.out_dir / "web-session-context.json", session_context)

        verified_outcomes = verified_outcomes_for_findings(findings)
        verified_outcomes_dict = {
            "count": len(verified_outcomes),
            "outcomes": [outcome.to_dict() for outcome in verified_outcomes],
        }
        save_json(self.out_dir / "verified-outcomes.json", verified_outcomes_dict)

        context_guard = build_web_context_guard_report(
            target=self.base_url,
            llm_enabled=self.llm is not None,
            auth_context=(
                "authenticated"
                if (self.session and self.session.authenticated)
                else "unauthenticated"
            ),
            reveal_secrets=bool(getattr(self.client, "reveal_secrets", False)),
            artifacts={
                "web_findings": str(self.out_dir / "web_findings.json"),
                "web_session_context": str(self.out_dir / "web-session-context.json"),
                "verified_outcomes": str(self.out_dir / "verified-outcomes.json"),
                "research_landscape": str(self.out_dir / "research_landscape.json"),
            },
        )
        save_json(self.out_dir / "context-guard-report.json", context_guard)

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
            "research_landscape": {
                "source_archive": research_landscape["source_archive"],
                "archive_years_reviewed": research_landscape["archive_years_reviewed"],
                "curation_mode": research_landscape["curation_mode"],
                "high_priority_themes": high_priority_theme_ids(research_landscape),
                "coverage": {
                    theme["id"]: theme["coverage"]
                    for theme in research_landscape["themes"]
                },
            },
            "web_session_context": {
                "url_count": session_context["surface"]["url_count"],
                "form_count": session_context["surface"]["form_count"],
                "parameter_count": session_context["surface"]["parameter_count"],
                "auth": session_context["auth"],
            },
            "verified_outcomes": {
                "count": len(verified_outcomes),
                "oracle": "web",
                "reproducible": False,
            },
            "context_guard": {
                "artifact": str(self.out_dir / "context-guard-report.json"),
                "target_content_is_untrusted": True,
            },
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


def build_arg_parser():
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
    parser.add_argument("--max-fuzz-urls", type=int, default=5)
    parser.add_argument("--max-fuzz-params", type=int, default=12)
    parser.add_argument("--max-fuzz-forms", type=int, default=5)
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

    ffuf = parser.add_argument_group("ffuf content discovery")
    ffuf.add_argument("--ffuf-wordlist")
    ffuf.add_argument("--ffuf-path", default="FUZZ")
    ffuf.add_argument("--ffuf-bin", default="ffuf")
    ffuf.add_argument("--ffuf-threads", type=int, default=10)
    ffuf.add_argument("--ffuf-rate", type=int)
    ffuf.add_argument("--ffuf-timeout", type=int, default=30)
    ffuf.add_argument("--ffuf-report-limit", type=int, default=50)
    ffuf.add_argument("--ffuf-max-runtime", type=int, default=300)
    ffuf.add_argument("--ffuf-no-auto-calibration", action="store_true")
    ffuf.add_argument("--ffuf-match-status", default="200,204,301,302,307,401,403,405,500")
    ffuf.add_argument("--ffuf-filter-status", default="404")
    ffuf.add_argument("--ffuf-filter-size", type=int)
    ffuf.add_argument("--ffuf-header", action="append", default=[])
    ffuf.add_argument("--ffuf-cookie", action="append", default=[])

    return parser


def build_ffuf_config(args):
    """Build an optional ffuf config from parsed CLI args."""
    if not getattr(args, "ffuf_wordlist", None):
        return None

    from packages.web.ffuf import FfufConfig

    def _blank_to_none(value):
        return None if value == "" else value

    return FfufConfig(
        wordlist=Path(args.ffuf_wordlist),
        path_template=args.ffuf_path,
        threads=args.ffuf_threads,
        rate=args.ffuf_rate,
        timeout=args.ffuf_timeout,
        max_runtime=args.ffuf_max_runtime,
        report_limit=args.ffuf_report_limit,
        binary=args.ffuf_bin,
        auto_calibration=not args.ffuf_no_auto_calibration,
        match_status=_blank_to_none(args.ffuf_match_status),
        filter_status=_blank_to_none(args.ffuf_filter_status),
        filter_size=args.ffuf_filter_size,
        headers=tuple(args.ffuf_header or ()),
        cookies=tuple(args.ffuf_cookie or ()),
    )


def main() -> int:
    parser = build_arg_parser()
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
        max_fuzz_urls=args.max_fuzz_urls,
        max_fuzz_params=args.max_fuzz_params,
        max_fuzz_forms=args.max_fuzz_forms,
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
