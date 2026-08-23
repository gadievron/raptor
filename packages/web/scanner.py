#!/usr/bin/env python3
"""Autonomous Web Application Security Scanner.

Runs a phased pipeline against a target web application:

  Phase 0   Preflight        -- reachability, telemetry reset
  Phase 1   Authentication   -- optional; form/bearer/cookie/basic
  Phase 2   Discovery        -- robots, sitemap, common paths, JS routes,
                                API specs, fingerprint
  Phase 2a  External discovery -- opt-in ffuf, seeds the crawl
  Phase 3   Crawl            -- BFS HTML crawl integrated with discovery
  Phase 4   Passive checks   -- ASVS-mapped checks without auth
  Phase 5   Auth checks      -- ASVS-mapped checks with a live session
  Phase 6a  Understand       -- optional URL-native context map
  Phase 6   Injection        -- three-gate oracle fuzzing of parameters/forms
  Phase 6v  Verification     -- mechanical replay/control verification of hits
  Phase 7a  Validate         -- optional /validate post-pass
  Phase 7b  External validation -- opt-in second-opinion validators (nuclei)
  Phase 7   Report           -- artifacts, evidence ledger, console summary
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from types import TracebackType
from urllib.parse import parse_qsl, urlparse

if __name__ == "__main__":
    # Direct script invocation only — module imports rely on the
    # caller's sys.path. Hard lookup per the path-safety rule
    # (CLAUDE.md): RAPTOR_DIR is the only permitted sys.path
    # addition, and a missing value must KeyError loudly rather than
    # fall back to a positional walk.
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.context_guard import build_web_context_guard_report
from core.json import save_json
from core.logging import get_logger
from core.run.safe_io import safe_run_mkdir
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from packages.web.auth import AuthenticationError, make_auth_manager
from packages.web.checks import registry
from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.discovery import Discoverer, DiscoveryResult
from packages.web.evidence import build_web_evidence_ledger
from packages.web.execution_policy import WebExecutionPolicy, WebPolicyError
from packages.web.external_validators import ExternalValidatorRunner, NucleiConfig
from packages.web.ffuf import FfufConfig, FfufRunner, parse_wordlist_args
from packages.web.fuzzer import WebFuzzer
from packages.web.models import WebFinding
from packages.web.research_landscape import (
    assess_research_landscape,
    high_priority_theme_ids,
)
from packages.web.session_context import build_web_session_context
from packages.web.tool_adapters import web_tool_adapter_report
from packages.web.verified_outcomes import verified_outcomes_for_findings

if TYPE_CHECKING:
    import argparse

    from core.llm.client import LLMClient
    from packages.web.auth import AuthManager, AuthSession
    from packages.web.checks.base import CheckResult

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
    "ssti": "CWE-1336",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
}


def _parse_oob_listen(spec: str) -> tuple[str, int]:
    """'PORT' or 'HOST:PORT' -> (bind_host, port); raises ValueError."""
    host, _, port_text = spec.rpartition(":")
    if not host:
        host = "0.0.0.0"  # noqa: S104 - callback listener binds wide by design
    try:
        port = int(port_text)
    except ValueError:
        msg = f"--oob-listen expects PORT or HOST:PORT, got {spec!r}"
        raise ValueError(msg) from None
    if not 0 <= port <= 65535:
        msg = f"--oob-listen port out of range: {port}"
        raise ValueError(msg)
    return host, port

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

_INJECTION_VULN_TYPES = ["sqli", "xss", "ssti", "command_injection", "path_traversal"]


class WebScanner:
    """Fully autonomous web application security scanner."""

    def __init__(
        self,
        base_url: str,
        llm: LLMClient | None = None,
        out_dir: Path | None = None,
        *,
        auth_manager: AuthManager | None = None,
        verify_ssl: bool = True,
        reveal_secrets: bool = False,
        block_private_ips: bool = True,
        rate_limit: float = 0.5,
        max_depth: int = 3,
        max_pages: int = 100,
        max_fuzz_urls: int = 5,
        max_fuzz_params: int = 12,
        max_fuzz_forms: int = 5,
        run_understand: bool = False,
        run_validate: bool = False,
        ffuf_config: FfufConfig | None = None,
        external_validators: list[str] | None = None,
        nuclei_config: NucleiConfig | None = None,
        approval_level: str = "active",
        approved_tools: list[str] | None = None,
        verify_findings: bool = True,
        max_verifications: int = 25,
        rank: bool = False,
        mine_params: bool = False,
        second_auth_manager: AuthManager | None = None,
        access_control: bool = False,
        ffuf_wordlist_dir: Path | None = None,
        ffuf_api_wordlist: Path | None = None,
        oob_listen: str | None = None,
        oob_callback_host: str | None = None,
        oob_grace: float = 10.0,
    ) -> None:
        import time

        self.base_url = base_url.rstrip("/")
        self.llm = llm
        self.out_dir = out_dir or Path("out") / f"web_scan_{int(time.time())}"
        self.out_dir.parent.mkdir(parents=True, exist_ok=True)
        safe_run_mkdir(self.out_dir)
        self.auth_manager = auth_manager
        self.reveal_secrets = reveal_secrets
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_fuzz_urls = max_fuzz_urls
        self.max_fuzz_params = max_fuzz_params
        self.max_fuzz_forms = max_fuzz_forms
        self.run_understand = run_understand
        self.run_validate = run_validate
        self.ffuf_config = ffuf_config
        self.external_validators = list(external_validators or [])
        self.nuclei_config = nuclei_config
        self.verify_findings = verify_findings
        self.max_verifications = max_verifications
        self.rank = rank
        self.mine_params = mine_params
        self.second_auth_manager = second_auth_manager
        self.access_control = access_control
        self.ffuf_wordlist_dir = ffuf_wordlist_dir
        self.ffuf_api_wordlist = ffuf_api_wordlist
        self.oob_grace = oob_grace
        self.oob_listener = None
        if oob_listen:
            from packages.web.oob import OobListener
            bind_host, bind_port = _parse_oob_listen(oob_listen)
            self.oob_listener = OobListener(
                bind_host=bind_host,
                port=bind_port,
                callback_host=oob_callback_host,
            )
        self._client_kwargs: dict[str, bool] = {
            "verify_ssl": verify_ssl,
            "reveal_secrets": reveal_secrets,
            "block_private_ips": block_private_ips,
        }
        self._client_rate_limit = rate_limit

        self.execution_policy = WebExecutionPolicy.for_target(
            self.base_url,
            approval_level=approval_level,
            approved_tools=approved_tools or [],
        )

        self.client = WebClient(
            base_url, verify_ssl=verify_ssl, reveal_secrets=reveal_secrets,
            block_private_ips=block_private_ips,
        )
        # Set after construction so test doubles that pin the WebClient
        # constructor signature stay valid; the client treats a missing
        # policy as "origin checks only".
        self.client.execution_policy = self.execution_policy
        self.client.rate_limit = rate_limit
        self.crawler = WebCrawler(self.client, max_depth=max_depth, max_pages=max_pages)
        # The fuzzer is always constructed: without an LLM it fuzzes with
        # static payloads, and the three-gate oracle keeps the false
        # positives out either way.
        self.fuzzer = WebFuzzer(self.client, llm)

        self.session: AuthSession | None = None
        self._phases_completed: list[str] = []
        self._finding_counter = 0
        self._external_tool_results: list[dict] = []
        self._ffuf_wordlist_used: str | None = None
        self._ffuf_hit_count = 0
        self._external_validation_results: list[dict] = []
        self._raw_injection_hits: list[dict] = []
        self._external_sensitive_candidates: list[tuple[str, str]] = []

        logger.info(
            "Web scanner initialized for %s (verify_ssl=%s, max_depth=%s, max_pages=%s)",
            base_url, verify_ssl, max_depth, max_pages,
        )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def scan(self) -> dict[str, Any]:
        """Run the complete autonomous web security scan."""
        logger.info("Starting autonomous web security scan")

        all_findings: list[WebFinding] = []

        if not self._phase_preflight():
            return self._empty_result("Preflight failed -- target unreachable")

        self._phase_auth()
        discovery = self._phase_discovery()
        self._sage_attach_priors()
        self._phase_external_discovery(discovery)
        crawl_data = self._phase_crawl(discovery)
        if self.mine_params:
            self._phase_param_mining(crawl_data)
        all_findings.extend(self._phase_passive_checks(discovery, crawl_data))

        if self.session and self.session.authenticated:
            all_findings.extend(self._phase_auth_checks(discovery, crawl_data))
        if self.access_control:
            all_findings.extend(
                self._phase_access_control(discovery, crawl_data)
            )

        context_map = None
        if self.run_understand:
            context_map = self._phase_understand(crawl_data, discovery)

        injection_findings = self._phase_injection(
            crawl_data, context_map=context_map, discovery=discovery,
        )
        all_findings.extend(injection_findings)

        verification_summary = None
        if self.verify_findings and self._raw_injection_hits:
            verification_summary = self._verify_findings(
                [
                    (hit, hit.get("endpoint", ""), hit.get("parameter", ""),
                     hit.get("method", "GET"))
                    for hit in self._raw_injection_hits
                ],
            )
            self._phases_completed.append("verification")
            self._annotate_findings_with_verification(injection_findings)

        all_findings.extend(self._phase_oob())

        if self.run_validate:
            all_findings = self._phase_validate(all_findings)

        self._phase_external_validation(all_findings)
        report = self._phase_report(all_findings, discovery, crawl_data)
        if verification_summary is not None:
            report["verification"] = verification_summary
            save_json(self.out_dir / "web_scan_report.json", report)
        return report

    def _phase_preflight(self) -> bool:
        logger.info("Phase 0: Preflight")
        try:
            from core.security.prompt_telemetry import defense_telemetry
            defense_telemetry.reset()
        except Exception:
            logger.debug("defense telemetry unavailable", exc_info=True)
        try:
            resp = self.client.get("/")
            logger.info(
                "Target reachable: HTTP %s (%d bytes)",
                resp.status_code, len(resp.content),
            )
            self._phases_completed.append("preflight")
            return True
        except Exception as e:
            logger.error("Preflight failed: %s", self._redact(str(e)))
            return False

    def _phase_auth(self) -> None:
        if not self.auth_manager:
            logger.info("Phase 1: Authentication -- skipped (unauthenticated scan)")
            return
        logger.info("Phase 1: Authentication")
        try:
            self.session = self.auth_manager.authenticate(self.client)
            logger.info("Authentication succeeded (mode: %s)", self.session.mode)
            self._phases_completed.append("authentication")
        except AuthenticationError as e:
            logger.warning(
                "Authentication failed -- continuing as unauthenticated: %s",
                self._redact(str(e)),
            )
            self.session = None

    def _phase_discovery(self) -> DiscoveryResult:
        logger.info("Phase 2: Discovery")
        result = Discoverer(self.client).discover(self.base_url)
        self._write_discovery_artifact(result)
        logger.info("Discovery stats: %s", result.stats())
        self._phases_completed.append("discovery")
        return result

    def _write_discovery_artifact(self, result: DiscoveryResult) -> None:
        """Persist the current discovery view, including external seeds."""
        save_json(self.out_dir / "discovery.json", {
            "stats": result.stats(),
            "urls": result.urls[:200],
            "fingerprint": result.fingerprint,
            "common_paths_found": result.common_paths_found,
            "robots_disallow": result.robots_disallow,
            "has_openapi": result.openapi_spec is not None,
            "has_graphql": result.graphql_schema is not None,
        })

    def _enriched_ffuf_config(
        self, discovery: DiscoveryResult,
    ) -> FfufConfig | None:
        """The run's ffuf config, enriched from the scan's own state.

        Fills only what the operator left empty — explicit flags always
        win: auth headers/cookies derive from the live session (the
        scan already authenticated; ffuf should not fuzz logged-out),
        extensions derive from the fingerprint, and when no wordlist
        was given but a wordlist DIRECTORY was, a conventionally-named
        list is selected per fingerprint. Every enrichment is logged.
        """
        from dataclasses import replace as _replace

        from packages.web.discovery.wordlists import (
            recommend_extensions,
            select_wordlist,
        )

        config = self.ffuf_config
        if config is None and self.ffuf_wordlist_dir is not None:
            chosen = select_wordlist(
                discovery.fingerprint or {}, self.ffuf_wordlist_dir,
            )
            if chosen is None:
                logger.info(
                    "Phase 2a: no wordlist matched under %s — ffuf stays off",
                    self.ffuf_wordlist_dir,
                )
                return None
            logger.info(
                "Phase 2a: fingerprint-selected wordlist %s (fingerprint: %s)",
                chosen.name, discovery.fingerprint or {},
            )
            config = FfufConfig(wordlist=chosen)
        if config is None:
            return None

        updates: dict = {}
        if not config.extensions:
            recommended = recommend_extensions(discovery.fingerprint or {})
            if recommended:
                updates["extensions"] = recommended
                logger.info(
                    "Phase 2a: fingerprint-recommended extensions %s",
                    ",".join(recommended),
                )
        if not config.headers and not config.cookies:
            updates.update(self._session_ffuf_credentials())
        if (
            config.filter_size is None
            and config.filter_words is None
            and config.filter_regex is None
        ):
            from packages.web.discovery.calibration import (
                derive_soft404_filters,
            )
            derived = derive_soft404_filters(self.client, self.base_url)
            if derived:
                updates.update(derived)
                logger.info(
                    "Phase 2a: soft-404 wildcard probes derived %s",
                    ", ".join(f"{k}={v}" for k, v in derived.items()),
                )
        return _replace(config, **updates) if updates else config

    def _session_ffuf_credentials(self) -> dict:
        """ffuf header/cookie updates carrying the live session's auth.

        The scan already authenticated; ffuf should not fuzz logged-out.
        """
        if not (self.session and self.session.authenticated):
            return {}
        if self.session.mode == "bearer" and self.session.token:
            logger.info("Phase 2a: ffuf reuses the session bearer token")
            return {"headers": (
                f"Authorization: Bearer {self.session.token}",
            )}
        if self.session.mode in ("form", "cookie"):
            jar = self.client.get_cookies()
            if jar:
                cookie = "; ".join(f"{k}={v}" for k, v in sorted(jar.items()))
                logger.info(
                    "Phase 2a: ffuf reuses %d session cookie(s)", len(jar),
                )
                return {"cookies": (cookie,)}
        return {}

    def _phase_external_discovery(self, discovery: DiscoveryResult) -> None:
        """Run opt-in external discovery tools and seed the crawl."""
        ffuf_config = self._enriched_ffuf_config(discovery)
        if not ffuf_config:
            return
        logger.info("Phase 2a: External content discovery (ffuf)")
        try:
            self.execution_policy.authorize(
                tool_id="ffuf",
                url=self.base_url,
                risk="active",
                action="external_discovery",
            )
            result = FfufRunner(
                self.base_url,
                self.out_dir,
                reveal_secrets=self.reveal_secrets,
            ).run(ffuf_config)
            self._external_tool_results.append(result)
            # Wordlist-effectiveness prior for SAGE: name only, never
            # the operator's filesystem path.
            self._ffuf_wordlist_used = ffuf_config.wordlist.name
            self._ffuf_hit_count = int(result.get("result_count") or 0)
            hit_urls = []
            for entry in result.get("results", []):
                url = entry.get("url")
                if not url:
                    continue
                hit_urls.append(url)
                if url not in discovery.urls:
                    discovery.urls.append(url)
            # Sensitive-looking hits become re-verification CANDIDATES for
            # SensitiveFileCheck — never findings by themselves. Paths the
            # common-paths probe already covered are excluded (they were
            # probed first-party in Phase 2).
            from packages.web.sensitive_paths import sensitive_candidates
            already = set(discovery.common_paths_found or [])
            self._external_sensitive_candidates = [
                (path, label)
                for path, label in sensitive_candidates(hit_urls)
                if path not in already
            ]
            if self._external_sensitive_candidates:
                logger.info(
                    "Phase 2a: %d sensitive-path candidate(s) handed to checks",
                    len(self._external_sensitive_candidates),
                )
            self._write_discovery_artifact(discovery)
            self._phases_completed.append("external_discovery")
        except (ValueError, OSError, WebPolicyError) as e:
            # A late ffuf failure must not discard the rest of the scan.
            logger.warning("External discovery skipped: %s", self._redact(str(e)))
            self._external_tool_results.append({
                "tool": "ffuf",
                "status": "error",
                "reason": str(e),
            })

    def _phase_crawl(self, discovery: DiscoveryResult) -> dict:
        logger.info("Phase 3: Crawl")
        seed_urls = self._maybe_rank(
            list(discovery.urls),
            "Which of these URLs are most worth crawling on a web security "
            "assessment? Prefer admin/API/dynamic endpoints with parameters "
            "over static assets and boilerplate.",
        )
        for url in seed_urls[:50]:
            self.crawler.discovered_urls.add(url)
        crawl_results = self.crawler.crawl(self.base_url)
        save_json(self.out_dir / "crawl_results.json", crawl_results)
        logger.info("Crawl stats: %s", crawl_results.get('stats', {}))
        self._phases_completed.append("crawl")
        return crawl_results

    def _phase_param_mining(self, crawl_data: dict) -> None:
        """Phase 3b: chunked differential mining of hidden parameters.

        Discovered names join crawl_data's parameter view so the checks
        and Phase 6 fuzz-cell construction see them like any crawled
        parameter. Unstable targets refuse to mine (differentials on a
        page that changes every request are noise, not parameters).
        """
        from packages.web.discovery.param_mining import mine_parameters

        logger.info("Phase 3b: Hidden-parameter mining")
        try:
            self.execution_policy.authorize(
                tool_id="raptor-http",
                url=self.base_url,
                risk="active",
                action="param_mining",
            )
        except WebPolicyError as e:
            logger.info("Phase 3b: skipped by execution policy -- %s", e)
            return
        known = set(crawl_data.get("discovered_parameters") or [])
        targets = list(dict.fromkeys(
            crawl_data.get("discovered_urls")
            or crawl_data.get("visited_urls")
            or [self.base_url]
        ))[:3]
        mined: set[str] = set()
        for url in targets:
            result = mine_parameters(self.client, url, known=known | mined)
            mined.update(result.discovered)
            if not result.stable:
                logger.info("Phase 3b: %s unstable; skipping", self._redact(url))
        if mined:
            crawl_data["discovered_parameters"] = sorted(known | mined)
            crawl_data.setdefault("mined_parameters", sorted(mined))
            stats = crawl_data.setdefault("stats", {})
            stats["total_parameters"] = len(crawl_data["discovered_parameters"])
        self._phases_completed.append("param_mining")

    def _merged_discovery_ctx(
        self, discovery: DiscoveryResult, crawl_data: dict | None,
    ) -> dict:
        """Discovery view merged with crawl results, for check context."""
        discovery_ctx = dict(discovery.__dict__)
        if crawl_data:
            discovery_ctx["parameters"] = list(set(
                list(discovery_ctx.get("parameters", []))
                + list(crawl_data.get("discovered_parameters", []))
            ))
            discovery_ctx["urls"] = list(set(
                list(discovery_ctx.get("urls", []))
                + list(crawl_data.get("visited_urls", []))
            ))
            discovery_ctx["forms"] = (
                list(discovery_ctx.get("forms", []))
                + list(crawl_data.get("discovered_forms", []))
            )
        discovery_ctx["external_paths"] = list(self._external_sensitive_candidates)
        return discovery_ctx

    def _phase_passive_checks(
        self, discovery: DiscoveryResult, crawl_data: dict | None = None,
    ) -> list[WebFinding]:
        logger.info("Phase 4: Passive security checks (unauthenticated)")
        findings = []
        check_classes = registry.unauthenticated()
        logger.info("Running %d unauthenticated checks", len(check_classes))
        discovery_ctx = self._merged_discovery_ctx(discovery, crawl_data)

        for cls in check_classes:
            try:
                results = cls(llm=self.llm).run(
                    self.client, self.base_url, session=None, discovery=discovery_ctx,
                )
                for r in results:
                    if not r.passed:
                        findings.append(self._to_finding(r, "unauthenticated"))
            except Exception as e:
                logger.debug("Check %s failed: %s", cls.__name__, self._redact(str(e)))
        logger.info("Phase 4 complete: %d findings", len(findings))
        self._phases_completed.append("passive_checks")
        return findings

    def _phase_auth_checks(
        self, discovery: DiscoveryResult, crawl_data: dict | None = None,
    ) -> list[WebFinding]:
        logger.info("Phase 5: Authenticated checks")
        if not self.session:
            return []
        if self.auth_manager and not self.auth_manager.verify(self.client, self.session):
            logger.warning("Session expired before authenticated checks -- skipping")
            return []
        findings = []
        check_classes = registry.authenticated()
        logger.info("Running %d authenticated checks", len(check_classes))
        discovery_ctx = self._merged_discovery_ctx(discovery, crawl_data)

        for cls in check_classes:
            try:
                results = cls(llm=self.llm).run(
                    self.client, self.base_url,
                    session=self.session, discovery=discovery_ctx,
                )
                for r in results:
                    if not r.passed:
                        findings.append(self._to_finding(r, "authenticated"))
            except Exception as e:
                logger.debug(
                    "Auth check %s failed: %s", cls.__name__, self._redact(str(e)),
                )
        logger.info("Phase 5 complete: %d findings", len(findings))
        self._phases_completed.append("auth_checks")
        return findings

    def _make_principal_client(self) -> WebClient:
        """A fresh client (separate cookie jar) sharing the scan's scope."""
        client = WebClient(
            self.base_url,
            verify_ssl=self._client_kwargs["verify_ssl"],
            reveal_secrets=self._client_kwargs["reveal_secrets"],
            block_private_ips=self._client_kwargs["block_private_ips"],
        )
        client.execution_policy = self.execution_policy
        client.rate_limit = self._client_rate_limit
        return client

    def _phase_access_control(
        self, discovery: DiscoveryResult, crawl_data: dict,
    ) -> list[WebFinding]:
        """Phase 5b: principal-differential access control (IDOR / 403).

        Always runs anonymous-vs-session-A when the scan authenticated;
        adds session B when a second credential set was supplied. All
        evidence is mechanical per-principal differentials — findings
        land as needs_review, never auto-confirmed.
        """
        from packages.web.access_control import (
            Principal,
            run_access_differential,
        )

        logger.info("Phase 5b: Access-control differential")
        if not (self.session and self.session.authenticated):
            logger.info("Phase 5b: skipped — no authenticated session to differ against")
            return []

        principals = [
            Principal("session_a", self.client, authenticated=True),
            Principal("anonymous", self._make_principal_client(), authenticated=False),
        ]
        if self.second_auth_manager is not None:
            try:
                second_client = self._make_principal_client()
                self.second_auth_manager.authenticate(second_client)
                principals.append(
                    Principal("session_b", second_client, authenticated=True)
                )
            except AuthenticationError as e:
                logger.warning(
                    "Phase 5b: second principal authentication failed: %s",
                    self._redact(str(e)),
                )

        merged = self._merged_discovery_ctx(discovery, crawl_data)
        result = run_access_differential(
            principals=principals,
            urls=list(merged.get("urls") or []),
            parameters=list(merged.get("parameters") or []),
            policy=self.execution_policy,
        )
        save_json(self.out_dir / "access-control-differential.json", {
            "targets_tested": result.targets_tested,
            "requests_used": result.requests_used,
            "findings": result.findings,
        })

        findings = []
        for hit in result.findings:
            self._finding_counter += 1
            if hit["kind"] == "idor_candidate":
                title = f"Object access not principal-scoped ({hit['other']})"
                detail = (
                    f"An object-scoped resource returned {hit['primary']}'s "
                    f"content unchanged to {hit['other']}."
                )
                check_id = "V4.2.1"
            else:
                title = f"Forbidden-resource bypass via {hit['primitive']}"
                detail = (
                    "A resource forbidden to the anonymous principal opened "
                    f"under the {hit['primitive']} rewrite primitive."
                )
                check_id = "V4.1.1"
            findings.append(WebFinding(
                id=f"WEB-{self._finding_counter:04d}",
                title=title,
                severity="high",
                confidence="medium",
                status="needs_review",
                url=hit["url"],
                evidence=str(hit["evidence"]),
                description=detail,
                recommendation=(
                    "Enforce object-level authorization server-side for every "
                    "principal on every request; normalize paths before "
                    "authorization decisions and ignore client-supplied "
                    "routing override headers."
                ),
                vuln_type="access_control",
                asvs_category="V4",
                check_id=check_id,
                auth_context="differential",
                cwe_id="CWE-639" if hit["kind"] == "idor_candidate" else "CWE-863",
                target_url=hit.get("bypass_url") or hit["url"],
                method="GET",
            ))
        logger.info("Phase 5b complete: %d findings", len(findings))
        self._phases_completed.append("access_control")
        return findings

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    def _phase_injection(
        self,
        crawl_data: dict,
        context_map: dict | None = None,
        discovery: DiscoveryResult | None = None,
    ) -> list[WebFinding]:
        logger.info("Phase 6: Injection and fuzzing")
        try:
            self.execution_policy.authorize(
                tool_id="raptor-web-oracle",
                url=self.base_url,
                risk="active",
                action="injection_fuzzing",
            )
        except WebPolicyError as e:
            logger.info("Phase 6: skipped by execution policy -- %s", e)
            self._phases_completed.append("injection_skipped")
            return []
        if not self.llm:
            logger.info("Phase 6: Running static fallback payloads -- no LLM available")
        auth_ctx = "authenticated" if self.session else "unauthenticated"

        # Collect raw hits keyed by (endpoint_url, vuln_type) so multiple
        # vulnerable parameters on the same endpoint collapse into one
        # finding. Values carry structured proof so the VerifiedOutcome
        # adapters consume findings without scraping prose.
        grouped: dict[tuple, dict] = {}

        def _record(endpoint: str, param: str, raw: dict, attack_vector: str) -> None:
            self._raw_injection_hits.append({
                **raw,
                "endpoint": endpoint,
                "parameter": param,
                "attack_vector": attack_vector,
            })
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
            for src, dst in (
                ("response_evidence", "response_evidence"),
                ("baseline_evidence", "baseline_evidence"),
                ("attack_evidence", "attack_evidence"),
                ("diff_summary", "diff_summaries"),
                ("oracle_signal", "oracle_signals"),
                ("method", "methods"),
            ):
                if raw.get(src):
                    grouped[key][dst].append(raw[src])
            if raw.get("status_code") is not None:
                grouped[key]["status_codes"].append(raw["status_code"])
            grouped[key]["attack_vectors"].append(attack_vector)

        # Build fuzz cells. Parameters are fuzzed at the URLs where the
        # crawler actually discovered them (`parameter_urls`); the
        # cross-product of prioritised URLs x global parameters is the
        # fallback when no mapping exists. Budgets bound both shapes.
        target_urls = list(dict.fromkeys(
            crawl_data.get("discovered_urls")
            or crawl_data.get("visited_urls")
            or [self.base_url]
        ))
        if self.base_url not in target_urls:
            target_urls.insert(0, self.base_url)

        global_params = self._prioritise_parameters(
            crawl_data.get("discovered_parameters", []),
            context_map=context_map,
        )[:self.max_fuzz_params]
        target_urls = self._maybe_rank(
            self._prioritise_urls(target_urls, global_params),
            "Which of these URLs are most likely to expose injection "
            "vulnerabilities (SQLi, XSS, SSTI, command injection, path "
            "traversal)? Prefer endpoints whose query parameters reach "
            "interpreters, filesystems, or shells.",
        )
        selected_urls = target_urls[:self.max_fuzz_urls]

        param_urls = crawl_data.get("parameter_urls")
        if not isinstance(param_urls, dict):
            param_urls = {}

        cells: list[tuple[str, str]] = []
        seen_cells: set[tuple[str, str]] = set()
        for target_url in selected_urls:
            own = self._query_parameters(target_url)
            candidates = self._maybe_rank(
                self._prioritise_parameters(
                    own + global_params, context_map=context_map,
                ),
                "Which of these HTTP parameter names most likely reach an "
                "interpreter, shell, filesystem, or database when fuzzed?",
            )[:self.max_fuzz_params]
            for param in candidates:
                mapped = param_urls.get(param)
                if mapped and target_url not in mapped and param not in own:
                    # The crawler knows where this parameter lives, and it
                    # is not here — skip the cell instead of spraying it.
                    continue
                cell = (target_url, param)
                if cell not in seen_cells:
                    seen_cells.add(cell)
                    cells.append(cell)

        forms = crawl_data.get("discovered_forms", [])[:self.max_fuzz_forms]
        logger.info(
            "Phase 6 budget: fuzzing %d URL(s), %d cell(s), %d form(s)",
            len(selected_urls), len(cells), len(forms),
        )

        for target_url, param in cells:
            for raw in self.fuzzer.fuzz_parameter(
                target_url, param, vulnerability_types=list(_INJECTION_VULN_TYPES),
            ):
                _record(raw.get("url", target_url), param, raw, "query_param")
        self._oob_inject(cells)

        for form in forms:
            endpoint = form.get("action", self.base_url)
            method = form.get("method", "GET")
            attack_vector = (
                "request_body" if str(method).upper() == "POST" else "query_param"
            )
            for field_name, field_info in form.get("inputs", {}).items():
                if field_info.get("type") in ("hidden", "submit", "button"):
                    continue
                for raw in self.fuzzer.fuzz_parameter(
                    endpoint, field_name,
                    param_type=field_info.get("type", "text"),
                    vulnerability_types=["sqli", "xss"], method=method,
                ):
                    _record(endpoint, field_name, raw, attack_vector)

        # Spec-driven API surface: parameters at their DOCUMENTED
        # locations. OpenAPI GET query params and string-typed JSON body
        # fields fuzz through the same three-gate oracle; GraphQL string
        # arguments probe via a fuzz-time full introspection.
        if discovery is not None and discovery.openapi_spec:
            from packages.web.api_testing import operations_from_openapi

            operations = operations_from_openapi(
                dict(discovery.openapi_spec), self.base_url,
            )[: self.max_fuzz_urls]
            logger.info(
                "Phase 6 API: %d OpenAPI operation(s) under test", len(operations),
            )
            self._api_scale_sweep(operations, _record)
            for op in operations:
                for param in op.query_params[: self.max_fuzz_params]:
                    for raw in self.fuzzer.fuzz_parameter(
                        op.url, param,
                        vulnerability_types=list(_INJECTION_VULN_TYPES),
                        method="GET" if op.method == "GET" else "POST",
                    ):
                        _record(op.url, param, raw, "api_query")
                if op.body_template:
                    for field_path in op.string_body_fields[: self.max_fuzz_params]:
                        for raw in self.fuzzer.fuzz_json_field(
                            op.url, op.body_template, field_path,
                        ):
                            _record(op.url, ".".join(field_path), raw, "json_body")
        if discovery is not None and discovery.graphql_endpoint:
            self._graphql_subpass(discovery.graphql_endpoint, _record)

        # Surface the memoisation win so operators can see the
        # redundant-probe reduction in the run log.
        try:
            cache_hits, cache_keys = self.fuzzer.payload_cache_stats
        except (TypeError, ValueError, AttributeError):
            cache_hits, cache_keys = 0, 0
        if cache_hits:
            logger.info(
                "Phase 6: payload generation memoised — %d LLM call(s) saved "
                "across %d unique (param, type, vuln) key(s)",
                cache_hits, cache_keys,
            )

        findings = [
            self._grouped_hit_to_finding(endpoint, vuln_type, hit, auth_ctx)
            for (endpoint, vuln_type), hit in grouped.items()
        ]
        logger.info(
            "Phase 6 complete: %d injection findings (%d total hits grouped)",
            len(findings), sum(len(h["params"]) for h in grouped.values()),
        )
        self._phases_completed.append("injection")
        return findings

    def _graphql_subpass(self, endpoint: str, record) -> None:
        """Fuzz-time full introspection + string-argument injection."""
        from packages.web.api_testing import (
            graphql_probes_from_schema,
            run_graphql_probes,
        )

        introspection = (
            "{__schema{queryType{name} types{name fields{name "
            "args{name type{name ofType{name}}}}}}}"
        )
        try:
            resp = self.client.post(
                endpoint, json_data={"query": introspection},
            )
            schema = resp.json()
        except Exception as e:
            logger.debug(
                "GraphQL introspection failed: %s", self._redact(str(e)),
            )
            return
        probes = graphql_probes_from_schema(schema)
        if not probes:
            return
        logger.info("Phase 6 API: %d GraphQL probe(s)", len(probes))
        for raw in run_graphql_probes(self.fuzzer, endpoint, probes):
            record(
                raw.get("url", endpoint), raw.get("parameter", ""),
                raw, "graphql_argument",
            )

    def _api_scale_sweep(self, operations: list, record) -> None:
        """ffuf-scale payload sweep over documented JSON body fields.

        Opt-in via --ffuf-api-sweep <payload-wordlist>. Per operation, a
        generated raw request file positions the keyword inside the
        first string body field — the spot -u/-d cannot express — and
        ffuf sweeps the operator's payload wordlist against it, matching
        only the static error-signature markers (classes whose signal
        needs a baseline leg are left to the in-Python oracle). Matched
        payloads are candidates, never findings: each replays first-party
        through the fuzzer's three-gate oracle, so a finding this path
        records carries the same evidence as native fuzzing. Payloads
        that break the JSON framing simply fail the match and cost
        nothing but a probe.
        """
        if self.ffuf_api_wordlist is None:
            return
        from packages.web.api_testing import (
            build_raw_request,
            sweep_match_regex,
        )

        eligible = [
            op for op in operations
            if op.body_template and op.string_body_fields
        ]
        if not eligible:
            return
        logger.info(
            "Phase 6 API: ffuf payload sweep over %d operation(s)",
            len(eligible),
        )
        try:
            self.execution_policy.authorize(
                tool_id="ffuf",
                url=self.base_url,
                risk="active",
                action="api_sweep",
            )
        except WebPolicyError as e:
            logger.warning("API sweep skipped: %s", self._redact(str(e)))
            return
        credentials = self._session_ffuf_credentials()
        for index, op in enumerate(eligible):
            field_path = op.string_body_fields[0]
            raw = build_raw_request(op, self.base_url, field_path)
            if raw is None:
                continue
            request_file = self.out_dir / f"api-sweep-{index:02d}.request"
            fd = os.open(
                request_file,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw)
            config = FfufConfig(
                wordlist=self.ffuf_api_wordlist,
                request_file=request_file,
                match_status=None,
                match_regex=sweep_match_regex(),
                max_runtime=120,
                report_limit=20,
                **credentials,
            )
            try:
                result = FfufRunner(
                    self.base_url,
                    self.out_dir,
                    reveal_secrets=self.reveal_secrets,
                ).run(config)
            except (ValueError, OSError) as e:
                logger.warning(
                    "API sweep skipped %s: %s", op.url, self._redact(str(e)),
                )
                continue
            payloads = [
                entry["input"]["FUZZ"]
                for entry in result.get("results", [])
                if isinstance(entry.get("input"), dict)
                and entry["input"].get("FUZZ")
            ]
            if not payloads:
                continue
            logger.info(
                "Phase 6 API sweep: %d candidate payload(s) at %s field %s "
                "— re-verifying first-party",
                len(payloads), op.url, ".".join(field_path),
            )
            for payload in payloads:
                finding = self.fuzzer.verify_json_candidate(
                    op.url, op.body_template, field_path, payload,
                )
                if finding:
                    record(
                        op.url, ".".join(field_path), finding,
                        "json_body_sweep",
                    )

    def _oob_inject(self, cells: list[tuple[str, str]]) -> None:
        """Blind-SSRF canaries: one minted callback URL per fuzz cell.

        Runs inside Phase 6 under its existing active-tier
        authorization. Injection only plants tokens — nothing is
        concluded here; correlation and replay verification happen in
        _phase_oob after the grace window.
        """
        if self.oob_listener is None:
            return
        from packages.web.oob import OobContext
        try:
            self.oob_listener.start()
        except OSError as e:
            logger.warning(
                "OOB listener failed to start (%s) — blind-SSRF probes "
                "skipped", self._redact(str(e)),
            )
            self.oob_listener = None
            return
        injected = 0
        for url, param in cells:
            try:
                canary = self.oob_listener.mint(
                    OobContext(url=url, param=param),
                )
                self.client.get(url, params={param: canary})
                injected += 1
            except Exception:
                logger.debug("OOB canary injection failed", exc_info=True)
        logger.info(
            "Phase 6: %d blind-SSRF canary URL(s) injected (callback base "
            "%s)", injected, self.oob_listener.callback_base,
        )

    def _phase_oob(self) -> list[WebFinding]:
        """Phase 6o: correlate callbacks, replay-verify, mint findings.

        One recorded callback proves nothing — crawler bots and
        security appliances fetch URLs they see. Verification re-injects
        with a FRESH token; only a new callback on that token upgrades
        the finding to verified. Everything else stays inconclusive and
        needs_review.
        """
        import time as _time

        listener = self.oob_listener
        if listener is None:
            return []
        from packages.web.attempts import (
            build_web_attempt,
            write_web_attempts,
        )
        from packages.web.oob import OobContext, OobHit, token_of
        from packages.web.oracle import VerificationResult
        findings: list[WebFinding] = []
        attempts = []
        try:
            stats = listener.stats
            if not stats["tokens_minted"]:
                return []
            logger.info(
                "Phase 6o: waiting %.0fs for out-of-band callbacks "
                "(%d canary token(s) live)",
                self.oob_grace, stats["tokens_minted"],
            )
            _time.sleep(self.oob_grace)
            for context, hit in listener.correlated():
                fresh = listener.mint(OobContext(
                    url=context.url, param=context.param, kind="ssrf-replay",
                ))
                replay_hit: OobHit | None = None
                try:
                    self.client.get(
                        context.url, params={context.param: fresh},
                    )
                    replay_hit = listener.wait_for(
                        token_of(fresh), timeout=max(5.0, self.oob_grace / 2),
                    )
                except Exception:
                    logger.debug("OOB replay leg failed", exc_info=True)
                verified = replay_hit is not None

                def _hit_record(h: OobHit) -> dict[str, Any]:
                    return {
                        "method": h.method,
                        "path": h.path,
                        "source_ip": h.source_ip,
                        "user_agent": h.user_agent,
                        "received_at": h.received_at,
                    }

                result = VerificationResult(
                    status="verified" if verified else "inconclusive",
                    evidence_type="oob_callback",
                    requests_used=2,
                    observations={
                        "first_callback": _hit_record(hit),
                        "replay_callback": (
                            _hit_record(replay_hit) if replay_hit else None
                        ),
                    },
                    reason=(
                        "fresh-token replay produced a new callback"
                        if verified else
                        "initial callback not reproduced with a fresh token"
                    ),
                )
                attempts.append(build_web_attempt(
                    url=context.url, param=context.param,
                    payload="oob-canary-url", vuln_type="ssrf",
                    method=context.method, result=result,
                    reveal_secrets=self.reveal_secrets,
                ))
                findings.append(
                    self._oob_finding(context, hit, replay_hit, verified),
                )
            if findings:
                write_web_attempts(attempts, self.out_dir)
            stats = listener.stats
            if stats["unknown_token_requests"]:
                logger.info(
                    "Phase 6o: %d request(s) with unknown/absent tokens "
                    "ignored", stats["unknown_token_requests"],
                )
            logger.info(
                "Phase 6o complete: %d callback finding(s) from %d minted "
                "token(s)", len(findings), stats["tokens_minted"],
            )
            self._phases_completed.append("oob")
        finally:
            listener.stop()
        return findings

    def _oob_finding(
        self, context, hit, replay_hit, verified: bool,
    ) -> WebFinding:
        auth_ctx = "authenticated" if self.session else "unauthenticated"
        self._finding_counter += 1
        replay_note = (
            f"Replay with a fresh token called back from "
            f"{replay_hit.source_ip} (User-Agent: {replay_hit.user_agent})"
            if replay_hit else
            "Replay with a fresh token produced no callback"
        )
        return WebFinding(
            id=f"WEB-{self._finding_counter:04d}",
            title="Blind SSRF -- server fetched an out-of-band canary URL",
            severity="high",
            confidence="high" if verified else "low",
            status="confirmed" if verified else "needs_review",
            url=context.url,
            evidence=(
                f"Canary URL injected into parameter '{context.param}' was "
                f"fetched server-side: {hit.method} {hit.path} from "
                f"{hit.source_ip} (User-Agent: {hit.user_agent}). "
                f"{replay_note}."
            ),
            description=(
                f"Parameter '{context.param}' caused the server to issue "
                "an outbound HTTP request to an attacker-controllable URL "
                "(server-side request forgery)."
            ),
            recommendation=(
                "Validate and allowlist outbound request destinations "
                "server-side; resolve and re-check redirects; block "
                "link-local and internal address ranges."
            ),
            vuln_type="ssrf",
            asvs_category="V12", check_id="V12.6.1",
            auth_context=auth_ctx,
            cwe_id=WEB_INJECTION_CWE["ssrf"],
            confirmed=verified,
            target_url=context.url,
            confirmation_payload="oob-canary-url",
            response_evidence=(
                f"callback from {hit.source_ip}: {hit.method} {hit.path}"
            ),
            attack_vector="oob_callback",
            method=context.method,
            affected_parameters=[context.param],
            oracle_signal=(
                "oob_callback_replayed" if verified else "oob_callback_once"
            ),
        )

    def _sage_attach_priors(self) -> None:
        """Attach per-target SAGE recall to the fuzzer — hint tier only.

        Recall reorders vulnerability classes and enriches payload
        prompts; it never suppresses a check or demotes a finding.
        Memory can prioritize; only this run's oracle can conclude.
        """
        try:
            from core.sage.hooks import recall_context_for_web_scan
            rows = recall_context_for_web_scan(self.base_url)
        except Exception:
            logger.debug("SAGE web recall unavailable", exc_info=True)
            return
        if not rows:
            return
        text = " | ".join(
            str(row.get("content") or "")[:300] for row in rows[:3]
        )
        self.fuzzer.set_sage_prior_recall(text, rows)
        logger.info(
            "SAGE prior: %d web recall row(s) attached (hint tier)",
            len(rows),
        )

    def _sage_store_observations(
        self, findings: list[WebFinding], discovery,
    ) -> None:
        """Store this run's web observations for future recalls."""
        try:
            from core.sage.hooks import store_web_scan_observations
            refuted_probes = [
                {
                    "vuln_type": hit.get("vulnerability_type"),
                    "endpoint": hit.get("endpoint"),
                }
                for hit in self._raw_injection_hits
                if (hit.get("verification") or {}).get("status") == "refuted"
            ]
            store_web_scan_observations(
                self.base_url,
                fingerprint=dict(
                    getattr(discovery, "fingerprint", None) or {},
                ),
                findings=[f.to_dict() for f in findings],
                refuted_probes=refuted_probes,
                wordlist_stats=self._wordlist_stats(),
            )
        except Exception:
            logger.debug("SAGE web store unavailable", exc_info=True)

    def _wordlist_stats(self) -> dict[str, int]:
        """Discovery hits per external wordlist run, for SAGE priors."""
        if self._ffuf_wordlist_used is None:
            return {}
        return {self._ffuf_wordlist_used: self._ffuf_hit_count}

    def _grouped_hit_to_finding(
        self, endpoint: str, vuln_type: str, hit: dict, auth_ctx: str,
    ) -> WebFinding:
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
        return WebFinding(
            id=f"WEB-{self._finding_counter:04d}",
            title=(
                f"{vuln_type.replace('_', ' ').title()} -- "
                f"{len(params)} parameter(s) affected"
            ),
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
                f"{len(params)} parameter(s) on this endpoint may be vulnerable "
                f"to {vuln_type.replace('_', ' ')}: {param_list}."
            ),
            recommendation=(
                "Validate and sanitise all user-supplied input server-side. "
                "Use parameterised queries for database access, "
                "context-appropriate output encoding for XSS, "
                "and allowlists for file/command parameters."
            ),
            vuln_type=vuln_type, asvs_category="V5", check_id="V5.2.1",
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
            affected_parameters=list(dict.fromkeys(params)),
            oracle_signal=oracle_signal,
            reproducible=False,
        )

    # ------------------------------------------------------------------
    # Phase 6v — mechanical verification (replay + control differential)
    # ------------------------------------------------------------------

    def _verify_findings(self, probe_contexts: list) -> dict[str, Any]:
        """Replay/control verification of injection hits.

        Annotates each raw hit dict in place with a ``verification``
        block, writes LabeledAttempt records for the run, and returns
        the summary for the report. Soft by design: nothing is
        dropped, and any per-hit failure degrades to ``inconclusive``.
        """
        from packages.web.attempts import build_web_attempt, write_web_attempts
        from packages.web.oracle import VerificationOracle

        logger.info(
            "Phase 6v: Verifying %d injection hit(s) (cap %d)",
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
                "%d hit(s) remain inconclusive/heuristic-tier",
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

    def _annotate_findings_with_verification(
        self, findings: list[WebFinding],
    ) -> None:
        """Fold per-hit replay verdicts into the grouped findings.

        A replay-verified hit upgrades the finding's confidence; a
        refuted-by-control verdict downgrades it. Findings are never
        dropped here — the verification block on the raw hits and the
        labeled-attempt records carry the mechanical verdicts.
        """
        by_endpoint: dict[tuple, list[dict]] = {}
        for hit in self._raw_injection_hits:
            key = (hit.get("endpoint"), hit.get("vulnerability_type"))
            by_endpoint.setdefault(key, []).append(hit)
        for finding in findings:
            hits = by_endpoint.get((finding.target_url, finding.vuln_type), [])
            statuses = {
                (h.get("verification") or {}).get("status") for h in hits
            } - {None}
            if not statuses:
                continue
            if "verified" in statuses:
                finding.confidence = "high"
            elif statuses == {"refuted"}:
                finding.confidence = "low"

    # ------------------------------------------------------------------
    # Optional phases
    # ------------------------------------------------------------------

    def _phase_understand(
        self, crawl_data: dict, discovery: DiscoveryResult,
    ) -> dict | None:
        """Build a URL-native context map for the discovered attack surface."""
        logger.info("Phase 6a: Building web context map")
        context_map = self._build_web_context_map(crawl_data, discovery)
        save_json(self.out_dir / "context-map.json", context_map)
        save_json(self.out_dir / "web-context-map.json", context_map)
        self._phases_completed.append("understand")
        return context_map

    def _phase_validate(self, findings: list[WebFinding]) -> list[WebFinding]:
        """Optional Phase 7a: run /validate on needs_review findings."""
        needs_review = [f for f in findings if f.status == "needs_review"]
        if not needs_review:
            return findings

        try:
            from core.security.rule_of_two import is_interactive
            if not is_interactive():
                logger.info(
                    "Phase 7a: /validate skipped -- non-interactive mode (Rule of Two)"
                )
                return findings
        except ImportError:
            return findings

        needs_review = self._maybe_rank(
            needs_review,
            "Which of these web findings are most likely real and "
            "exploitable, and most worth validation effort?",
            render=lambda f: (
                f"{f.vuln_type} {f.title} at {f.url} "
                f"oracle={f.oracle_signal or '-'}"
            )[:300],
        )
        logger.info("Phase 7a: Validating %d needs_review findings", len(needs_review))
        try:
            import shutil

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
            logger.debug("Phase 7a: /validate failed: %s", self._redact(str(e)))

        return findings

    def _phase_external_validation(self, findings: list[WebFinding]) -> None:
        """Run selected second-opinion validators against existing findings."""
        if not self.external_validators:
            return
        logger.info(
            "Phase 7b: External validation oracles (%s)",
            ", ".join(self.external_validators),
        )
        runner = ExternalValidatorRunner(
            base_url=self.base_url,
            out_dir=self.out_dir,
            policy=self.execution_policy,
            reveal_secrets=self.reveal_secrets,
            nuclei_config=self.nuclei_config,
        )
        self._external_validation_results = runner.run(
            findings, self.external_validators,
        )
        save_json(self.out_dir / "external-validator-results.json", {
            "results": self._external_validation_results,
            "note": "External validator no-match results are not refutations.",
        })
        self._phases_completed.append("external_validation")

    # ------------------------------------------------------------------
    # Context map + prioritisation
    # ------------------------------------------------------------------

    def _build_web_context_map(
        self, crawl_data: dict, discovery: DiscoveryResult,
    ) -> dict:
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

        entry_points: list[dict[str, Any]] = [
            {"type": "url", "url": url} for url in urls[:100]
        ]
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

        return {
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

    def _prioritise_parameters(
        self,
        parameters: list[str],
        context_map: dict | None = None,
    ) -> list[str]:
        if not context_map:
            return self._rank_parameters(list(parameters))

        sink_params = [
            sink["parameter"]
            for sink in context_map.get("sinks", [])
            if sink.get("parameter")
        ]
        ordered = []
        for param in sink_params + self._rank_parameters(list(parameters)):
            if param not in ordered:
                ordered.append(param)
        return ordered

    def _rank_parameters(self, parameters: list[str]) -> list[str]:
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

    def _prioritise_urls(self, urls: list[str], parameters: list[str]) -> list[str]:
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
            for chunk in parsed.path.lower().replace("-", "_").split("/")
            for token in chunk.split("_")
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

    def _query_parameters(self, url: str) -> list[str]:
        return [
            name
            for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True)
            if name
        ]

    def _maybe_rank(
        self,
        items: list,
        query: str,
        render=None,
    ) -> list:
        """Listwise-rank *items* when --rank is on and an LLM is present.

        Ordering only — the heuristic pre-order is the input, budgets and
        verdicts stay authoritative, and any ranking failure keeps the
        heuristic order. Rendered content is attacker-influenced (URLs,
        parameter names), so renders are size-capped per the ranking
        module's threat-model caveat.
        """
        if not self.rank or not self.llm or len(items) < 3:
            return items
        try:
            from core.llm.ranking import rank_items

            result = rank_items(
                items,
                query,
                client=self.llm,
                render=render or (lambda item: str(item)[:200]),
            )
            return [ranked.item for ranked in result.ranked]
        except Exception as e:
            logger.warning(
                "Ranking unavailable, keeping heuristic order: %s",
                self._redact(str(e)),
            )
            return items

    def _web_finding_to_agentic_result(self, finding: WebFinding) -> dict[str, Any]:
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

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _phase_report(self, findings, discovery, crawl_data) -> dict[str, Any]:
        logger.info("Phase 7: Report")
        self._sage_store_observations(findings, discovery)
        findings_dicts = [f.to_dict() for f in findings]
        save_json(self.out_dir / "web_findings.json", {"findings": findings_dicts})
        # Core-schema findings.json: this is what /project findings, diff,
        # correlate, and the merged report read (dedup key: file, function,
        # line, vuln_type). WebFinding.to_dict already aliases file=url;
        # the function analog for web is the check id (posture findings)
        # or the primary affected parameter (injection findings).
        save_json(self.out_dir / "findings.json", {"findings": [
            {
                **d,
                "function": (
                    (d.get("affected_parameters") or [None])[0]
                    or d.get("check_id") or ""
                ),
                "line": 0,
            }
            for d in findings_dicts
        ]})
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
        save_json(self.out_dir / "verified-outcomes.json", {
            "count": len(verified_outcomes),
            "outcomes": [outcome.to_dict() for outcome in verified_outcomes],
        })
        # Confirmed oracle-proven findings also enter the labeled-attempts
        # pool when the replay pass did not already write attempt records
        # for the run (verify_findings off).
        if not self.verify_findings:
            self._write_finding_attempts(findings)

        # Portable PoC artifacts: curl reproducer + nuclei replay template
        # per oracle-proven finding (soft; 0600 — payloads may carry
        # credentials).
        from packages.web.poc import write_web_pocs
        poc_paths = write_web_pocs(
            findings, self.out_dir, reveal_secrets=self.reveal_secrets,
        )

        execution_policy = self.execution_policy.report()
        save_json(self.out_dir / "scope-receipt.json", execution_policy["scope_receipt"])
        save_json(self.out_dir / "web-execution-policy.json", execution_policy)
        selected_adapters = ["raptor-http", "raptor-crawler", "raptor-web-oracle"]
        if self.ffuf_config or self.ffuf_wordlist_dir:
            selected_adapters.append("ffuf")
        selected_adapters.extend(self.external_validators)
        adapter_report = web_tool_adapter_report(selected_adapters)
        save_json(self.out_dir / "web-tool-adapters.json", {"adapters": adapter_report})
        save_json(self.out_dir / "external-tool-results.json", {
            "discovery": self._external_tool_results,
            "validators": self._external_validation_results,
        })

        evidence_ledger = build_web_evidence_ledger(
            findings=findings,
            request_history=list(getattr(self.client, "request_history", []) or []),
            external_validation=self._external_validation_results,
            execution_policy=execution_policy,
        )
        save_json(self.out_dir / "web-evidence-ledger.json", evidence_ledger)

        context_guard = build_web_context_guard_report(
            target=self.base_url,
            llm_enabled=self.llm is not None,
            auth_context=(
                "authenticated"
                if (self.session and self.session.authenticated)
                else "unauthenticated"
            ),
            reveal_secrets=self.reveal_secrets,
            artifacts={
                "web_findings": str(self.out_dir / "web_findings.json"),
                "web_session_context": str(self.out_dir / "web-session-context.json"),
                "verified_outcomes": str(self.out_dir / "verified-outcomes.json"),
                "research_landscape": str(self.out_dir / "research_landscape.json"),
                "scope_receipt": str(self.out_dir / "scope-receipt.json"),
                "execution_policy": str(self.out_dir / "web-execution-policy.json"),
                "tool_adapters": str(self.out_dir / "web-tool-adapters.json"),
                "external_tool_results": str(self.out_dir / "external-tool-results.json"),
                "evidence_ledger": str(self.out_dir / "web-evidence-ledger.json"),
            },
        )
        save_json(self.out_dir / "context-guard-report.json", context_guard)

        try:
            from core.security.prompt_telemetry import defense_telemetry
            defense_telemetry.write_summary(self.out_dir)
        except Exception:
            logger.debug("defense telemetry summary unavailable", exc_info=True)
        self._phases_completed.append("report")

        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        discovery_summary = dict(discovery.stats())
        discovery_summary.setdefault(
            "total_pages",
            crawl_data.get("stats", {}).get("total_pages", 0),
        )
        discovery_summary.setdefault(
            "total_parameters",
            crawl_data.get("stats", {}).get("total_parameters", 0),
        )

        result = {
            "target": self.base_url,
            "findings": findings_dicts,
            "total_findings": len(findings),
            "total_vulnerabilities": len(findings),
            "auth_context": (
                "authenticated"
                if (self.session and self.session.authenticated)
                else "unauthenticated"
            ),
            "discovery": discovery_summary,
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
            "execution_policy": {
                "scope_receipt": str(self.out_dir / "scope-receipt.json"),
                "approval_level": execution_policy["scope_receipt"]["approval_level"],
                "allowed_origins": execution_policy["scope_receipt"]["allowed_origins"],
                "allowed_actions": execution_policy["summary"]["allowed_actions"],
                "denied_actions": execution_policy["summary"]["denied_actions"],
            },
            "tool_adapters": {
                "artifact": str(self.out_dir / "web-tool-adapters.json"),
                "selected": selected_adapters,
            },
            "external_tools": {
                "discovery": self._external_tool_results,
                "validators": self._external_validation_results,
            },
            "evidence_ledger": {
                "artifact": str(self.out_dir / "web-evidence-ledger.json"),
                "confirmed_web_oracle_findings":
                    evidence_ledger["summary"]["confirmed_web_oracle_findings"],
                "external_validator_runs":
                    evidence_ledger["summary"]["external_validator_runs"],
            },
            "context_guard": {
                "artifact": str(self.out_dir / "context-guard-report.json"),
                "target_content_is_untrusted": True,
            },
            "pocs": {
                "count": len(poc_paths),
                "dir": str(self.out_dir / "pocs"),
                "note": "Live-target replay requires fresh operator authorisation.",
            },
        }
        # Back-compat report key: the first ffuf run's compact summary.
        for tool_result in self._external_tool_results:
            if tool_result.get("tool") == "ffuf":
                result["ffuf"] = tool_result
                break
        save_json(self.out_dir / "web_scan_report.json", result)
        logger.info(
            "Scan complete. %d findings. Report: %s", len(findings), self.out_dir,
        )
        return result

    def _write_finding_attempts(self, findings: list[WebFinding]) -> None:
        """Oracle-proven findings -> labeled-attempt records (soft)."""
        from packages.web.attempts import (
            build_attempt_from_confirmed_finding,
            write_web_attempts,
        )

        attempts = []
        for finding in findings:
            try:
                attempt = build_attempt_from_confirmed_finding(
                    finding, reveal_secrets=self.reveal_secrets,
                )
            except Exception:
                logger.debug("finding attempt build failed", exc_info=True)
                continue
            if attempt is not None:
                attempts.append(attempt)
        if attempts:
            write_web_attempts(attempts, self.out_dir)

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

    def _empty_result(self, reason: str) -> dict[str, Any]:
        return {
            "target": self.base_url, "findings": [], "total_findings": 0,
            "total_vulnerabilities": 0, "auth_context": "unauthenticated",
            "discovery": {}, "crawl": {}, "findings_by_severity": {},
            "phases_completed": self._phases_completed, "error": reason,
        }

    def _redact(self, value: str) -> str:
        from core.security.redaction import redact_secrets
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
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
        action="append",
        default=[],
        help=(
            "Opt-in ffuf content discovery wordlist; ffuf is only run when "
            "this is set. Repeatable: the first wordlist uses the implicit "
            "FUZZ keyword, additional ones take a path:KEYWORD suffix "
            "(e.g. params.txt:W2) for multi-wordlist fuzzing."
        ),
    )
    parser.add_argument(
        "--ffuf-mode",
        choices=("clusterbomb", "pitchfork"),
        help=(
            "Multi-wordlist combination mode for -mode; only valid with "
            "more than one --ffuf-wordlist (default: clusterbomb). "
            "Clusterbomb applies a default -rate of 50 req/s unless "
            "--ffuf-rate is set."
        ),
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
        "--ffuf-recursion",
        action="store_true",
        help=(
            "Enable ffuf recursive directory discovery; requires the URL "
            "template to end with FUZZ. Applies a default -rate of 50 req/s "
            "unless --ffuf-rate is set."
        ),
    )
    parser.add_argument(
        "--ffuf-recursion-depth",
        type=int,
        default=2,
        help="ffuf recursion depth (default: 2)",
    )
    parser.add_argument(
        "--ffuf-recursion-strategy",
        choices=("default", "greedy"),
        default="default",
        help="ffuf recursion strategy (default: default)",
    )
    parser.add_argument(
        "--ffuf-maxtime-job",
        type=int,
        help=(
            "Per-job runtime cap in seconds for -maxtime-job; defaults to "
            "max(60, max-runtime/4) when recursion is enabled"
        ),
    )
    parser.add_argument(
        "--ffuf-extensions",
        help="Comma-separated file extensions for ffuf -e, e.g. '.php,.bak,.old'",
    )
    parser.add_argument(
        "--ffuf-filter-words",
        type=int,
        help="Optional ffuf response word-count filter for -fw",
    )
    parser.add_argument(
        "--ffuf-filter-lines",
        type=int,
        help="Optional ffuf response line-count filter for -fl",
    )
    parser.add_argument(
        "--ffuf-match-regex",
        help="Optional ffuf response-content match regex for -mr (Go regexp syntax)",
    )
    parser.add_argument(
        "--ffuf-filter-regex",
        help="Optional ffuf response-content filter regex for -fr (Go regexp syntax)",
    )
    parser.add_argument(
        "--ffuf-match-time",
        help="Optional ffuf response-time matcher for -mt, e.g. '>500' (milliseconds)",
    )
    parser.add_argument(
        "--ffuf-filter-time",
        help="Optional ffuf response-time filter for -ft, e.g. '<100' (milliseconds)",
    )
    parser.add_argument(
        "--ffuf-stop-on-403",
        action="store_true",
        help="Stop ffuf when >95%% of responses return 403 (-sf); typical WAF signal",
    )
    parser.add_argument(
        "--ffuf-stop-on-spurious-errors",
        action="store_true",
        help="Stop ffuf on spurious errors (-se)",
    )
    parser.add_argument(
        "--ffuf-stop-on-all-errors",
        action="store_true",
        help="Stop ffuf on all error cases (-sa)",
    )
    parser.add_argument(
        "--ffuf-request",
        type=Path,
        help=(
            "Raw HTTP request file for ffuf -request mode (its Host must "
            "name the target; FUZZ may sit anywhere in the request). "
            "Mutually exclusive with --ffuf-path/-method/-data/vhost/"
            "recursion."
        ),
    )
    parser.add_argument(
        "--ffuf-api-sweep",
        type=Path,
        help=(
            "Payload wordlist for the OpenAPI body sweep: ffuf fuzzes "
            "each documented JSON string field via a generated raw "
            "request, matching static error signatures; hits are "
            "re-verified first-party before they can become findings"
        ),
    )
    parser.add_argument(
        "--oob-listen",
        help=(
            "Start the in-process out-of-band callback listener on "
            "PORT or HOST:PORT (0 = ephemeral) and inject blind-SSRF "
            "canary URLs during fuzzing; callbacks are replay-verified "
            "with fresh tokens before a finding is confirmed"
        ),
    )
    parser.add_argument(
        "--oob-callback-host",
        help=(
            "Externally reachable HOST[:PORT] the target should call "
            "back to, when it differs from the bind address (NAT, "
            "container, port-forward)"
        ),
    )
    parser.add_argument(
        "--oob-grace",
        type=float,
        default=10.0,
        help="Seconds to wait for out-of-band callbacks after fuzzing "
             "(default 10)",
    )
    parser.add_argument(
        "--ffuf-calibration-strategy",
        choices=("basic", "advanced"),
        help="ffuf auto-calibration strategy (-acs); advanced helps recursion",
    )
    parser.add_argument(
        "--ffuf-per-host-calibration",
        action="store_true",
        help="Calibrate filters per host (-ach); useful with vhost mode",
    )
    parser.add_argument(
        "--ffuf-encoder",
        action="append",
        default=[],
        help=(
            "Keyword encoder chain for -enc, e.g. 'FUZZ:urlencode' or "
            "'W2:urlencode b64encode' (repeatable)"
        ),
    )
    parser.add_argument(
        "--ffuf-vhost",
        action="store_true",
        help=(
            "Virtual-host discovery: keep the URL fixed and fuzz the Host "
            "header as FUZZ.<target-host>. Pair with the default -ac and "
            "--ffuf-filter-size of the wildcard response for clean output."
        ),
    )
    parser.add_argument(
        "--ffuf-vhost-host-template",
        help=(
            "Custom Host header template for --ffuf-vhost; must contain a "
            "wordlist keyword and end with .<target-host> "
            "(default: FUZZ.<target-host>)"
        ),
    )
    parser.add_argument(
        "--ffuf-method",
        default="GET",
        choices=("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
        help="HTTP method for ffuf requests (-X); default GET",
    )
    parser.add_argument(
        "--ffuf-data",
        help=(
            "Request body for ffuf -d; may contain FUZZ for parameter "
            "discovery, e.g. 'FUZZ=1' with --ffuf-method POST. Set the "
            "Content-Type via --ffuf-header."
        ),
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
        help="Skip the replay/control verification pass on injection hits",
    )
    parser.add_argument(
        "--max-verifications",
        type=int,
        default=25,
        help="Maximum hits to verify per run; the rest are marked skipped (default: 25)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM payload generation; the fuzzer uses static payloads",
    )
    parser.add_argument(
        "--ffuf-wordlist-dir",
        type=Path,
        help=(
            "Operator wordlist directory (e.g. a SecLists checkout): when "
            "no --ffuf-wordlist is given, a conventionally-named list is "
            "selected per the target's fingerprint"
        ),
    )
    parser.add_argument(
        "--mine-params",
        action="store_true",
        help=(
            "Chunked differential mining of hidden parameters after the "
            "crawl (active; ~60 requests per mined URL, first 3 URLs)"
        ),
    )
    parser.add_argument(
        "--rank",
        action="store_true",
        help=(
            "Listwise LLM ranking of crawl seeds, fuzz targets, and "
            "findings before each budget cap (ordering only; needs an LLM)"
        ),
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.5,
        help="Seconds between client requests (default: 0.5)",
    )
    parser.add_argument(
        "--max-fuzz-urls", type=int, default=5,
        help="Phase 6 budget: URLs to fuzz (default: 5)",
    )
    parser.add_argument(
        "--max-fuzz-params", type=int, default=12,
        help="Phase 6 budget: parameters per URL (default: 12)",
    )
    parser.add_argument(
        "--max-fuzz-forms", type=int, default=5,
        help="Phase 6 budget: forms to fuzz (default: 5)",
    )
    parser.add_argument(
        "--approval-level",
        choices=("passive", "active", "intrusive"),
        default="active",
        help="Scope-receipt approval level for live actions (default: active)",
    )
    parser.add_argument(
        "--approve-tool",
        action="append",
        default=[],
        help="Explicitly approve a tool above the approval level (repeatable)",
    )
    parser.add_argument(
        "--validator",
        action="append",
        default=[],
        choices=["nuclei"],
        help="Second-opinion external validator to run on findings (repeatable)",
    )

    parser.add_argument(
        "--access-control",
        action="store_true",
        help=(
            "Principal-differential access-control testing (IDOR / 403 "
            "bypass): session-A vs anonymous, plus session-B when the "
            "second-credential group is set. Requires an authenticated scan."
        ),
    )

    ag = parser.add_argument_group("authentication")
    ag.add_argument(
        "--auth-mode",
        default="none",
        choices=("none", "form", "bearer", "cookie", "basic"),
        help="Authentication mode for the scan session",
    )
    ag.add_argument("--login-url", help="Login form URL (form mode)")
    ag.add_argument("--logout-url", help="Logout URL used to detect session loss")
    ag.add_argument("--username", help="Username (form/basic modes)")
    ag.add_argument("--password", help="Password (form/basic modes)")
    ag.add_argument("--token", help="Bearer token (bearer mode)")
    ag.add_argument("--cookies", help="Cookie string 'a=1; b=2' (cookie mode)")
    ag.add_argument("--username-field", default="username",
                    help="Login form username field name (default: username)")
    ag.add_argument("--password-field", default="password",
                    help="Login form password field name (default: password)")

    bg = parser.add_argument_group("second principal (access-control differential)")
    bg.add_argument("--auth-b-mode", default="none",
                    choices=("none", "form", "bearer", "cookie", "basic"),
                    help="Second principal's authentication mode")
    bg.add_argument("--auth-b-username", help="Second principal username")
    bg.add_argument("--auth-b-password", help="Second principal password")
    bg.add_argument("--auth-b-token", help="Second principal bearer token")
    bg.add_argument("--auth-b-cookies", help="Second principal cookie string")

    adv = parser.add_argument_group("advanced pipeline")
    adv.add_argument(
        "--understand", action="store_true",
        help="Build a URL-native context map before injection fuzzing",
    )
    adv.add_argument(
        "--validate", action="store_true",
        help="Run the /validate post-pass on needs_review findings",
    )

    ng = parser.add_argument_group("nuclei validator")
    ng.add_argument(
        "--nuclei-templates",
        type=Path,
        help=(
            "Pinned nuclei templates directory (REQUIRED for --validator "
            "nuclei; templates are never fetched or auto-updated)"
        ),
    )
    ng.add_argument(
        "--nuclei-rate-limit", type=int, default=50,
        help="nuclei requests/second (-rl; default: 50)",
    )
    ng.add_argument(
        "--nuclei-severity", default="medium,high,critical",
        help="nuclei -severity filter (default: medium,high,critical)",
    )
    ng.add_argument(
        "--nuclei-max-runtime", type=int, default=600,
        help="Maximum sandboxed nuclei runtime in seconds (default: 600)",
    )
    return parser


def build_ffuf_config(args: "argparse.Namespace") -> FfufConfig | None:
    """Convert parsed CLI args into an optional ffuf configuration."""
    if not args.ffuf_wordlist:
        return None
    wordlist, extra_wordlists = parse_wordlist_args(args.ffuf_wordlist)
    # Resolve symlinks NOW so the parse-time preflight validates exactly
    # the paths the run will use (a symlink whose TARGET contains ':' or
    # ',' must fail here, not in Phase 2b). run() re-resolves, which is
    # idempotent on already-resolved paths.
    wordlist = Path(os.path.realpath(wordlist))
    extra_wordlists = tuple(
        (Path(os.path.realpath(path)), keyword) for path, keyword in extra_wordlists
    )
    return FfufConfig(
        wordlist=wordlist,
        extra_wordlists=extra_wordlists,
        mode=args.ffuf_mode,
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
        method=args.ffuf_method,
        data=args.ffuf_data,
        request_file=args.ffuf_request,
        calibration_strategy=args.ffuf_calibration_strategy,
        calibration_per_host=bool(args.ffuf_per_host_calibration),
        encoders=tuple(args.ffuf_encoder or ()),
        vhost=bool(args.ffuf_vhost),
        vhost_host_template=args.ffuf_vhost_host_template,
        stop_on_403=bool(args.ffuf_stop_on_403),
        stop_on_spurious=bool(args.ffuf_stop_on_spurious_errors),
        stop_on_all_errors=bool(args.ffuf_stop_on_all_errors),
        extensions=tuple(
            ext.strip() for ext in (args.ffuf_extensions or "").split(",") if ext.strip()
        ),
        recursion=bool(args.ffuf_recursion),
        recursion_depth=args.ffuf_recursion_depth,
        recursion_strategy=args.ffuf_recursion_strategy,
        max_runtime_job=args.ffuf_maxtime_job,
        filter_words=args.ffuf_filter_words,
        filter_lines=args.ffuf_filter_lines,
        match_regex=args.ffuf_match_regex,
        filter_regex=args.ffuf_filter_regex,
        match_time=args.ffuf_match_time,
        filter_time=args.ffuf_filter_time,
    )


def main():
    """CLI entry point for web scanner."""
    import time

    from core.config import RaptorConfig

    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        ffuf_config = build_ffuf_config(args)
        if ffuf_config is not None:
            # Preflight the full ffuf argv now: ffuf runs AFTER the
            # crawl/fuzz phases, and a config error surfacing there
            # aborts the scan and discards everything those phases
            # produced. build_command exercises every validation rule
            # without spawning anything.
            FfufRunner(
                args.url, Path("."), reveal_secrets=bool(args.reveal_secrets)
            ).build_command(ffuf_config, Path("ffuf-preflight.json"))
    except (ValueError, FileNotFoundError) as exc:
        parser.error(f"ffuf: {exc}")
    if args.ffuf_api_sweep is not None and not args.ffuf_api_sweep.is_file():
        # Same parse-time rule as the main ffuf preflight: the sweep
        # runs after crawl+fuzz, far too late to discover a bad path.
        parser.error(
            f"ffuf: --ffuf-api-sweep wordlist not found: {args.ffuf_api_sweep}"
        )
    if args.oob_listen is not None:
        try:
            _parse_oob_listen(args.oob_listen)
        except ValueError as exc:
            parser.error(str(exc))

    # Auth manager + nuclei knobs fail at parse time too, for the same
    # reason as the ffuf preflight: a bad flag combination must not cost
    # a crawl.
    try:
        auth_manager = make_auth_manager(
            args.auth_mode,
            username=args.username,
            password=args.password,
            token=args.token,
            cookies=args.cookies,
            login_url=args.login_url,
            logout_url=args.logout_url,
            username_field=args.username_field,
            password_field=args.password_field,
        )
    except ValueError as exc:
        parser.error(f"auth: {exc}")
    try:
        second_auth_manager = make_auth_manager(
            args.auth_b_mode,
            username=args.auth_b_username,
            password=args.auth_b_password,
            token=args.auth_b_token,
            cookies=args.auth_b_cookies,
            login_url=args.login_url,
            logout_url=args.logout_url,
            username_field=args.username_field,
            password_field=args.password_field,
        )
    except ValueError as exc:
        parser.error(f"auth-b: {exc}")
    nuclei_config = None
    if "nuclei" in (args.validator or []):
        if not args.nuclei_templates or not Path(args.nuclei_templates).is_dir():
            parser.error(
                "nuclei: --nuclei-templates must name a pinned templates "
                "directory (templates are never fetched or auto-updated)"
            )
        nuclei_config = NucleiConfig(
            templates_dir=args.nuclei_templates,
            rate_limit=args.nuclei_rate_limit,
            severity=args.nuclei_severity,
            max_runtime=args.nuclei_max_runtime,
        )

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
    llm = None
    if not args.no_llm:
        from core.llm.factory import get_client
        llm = get_client()
    if llm:
        logger.info("LLM client initialized")
    else:
        print("\n⚠️  Warning: no LLM client", file=sys.stderr)
        print("    Fuzzing runs with static payloads", file=sys.stderr)

    # Run scan
    verify_ssl = not args.insecure

    scanner = WebScanner(
        args.url,
        llm,
        out_dir,
        auth_manager=auth_manager,
        verify_ssl=verify_ssl,
        reveal_secrets=bool(args.reveal_secrets),
        rate_limit=args.rate_limit,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        max_fuzz_urls=args.max_fuzz_urls,
        max_fuzz_params=args.max_fuzz_params,
        max_fuzz_forms=args.max_fuzz_forms,
        run_understand=bool(args.understand),
        run_validate=bool(args.validate),
        ffuf_config=ffuf_config,
        external_validators=list(args.validator or []),
        nuclei_config=nuclei_config,
        approval_level=args.approval_level,
        approved_tools=list(args.approve_tool or []),
        verify_findings=not args.no_verify,
        max_verifications=args.max_verifications,
        rank=bool(args.rank),
        mine_params=bool(args.mine_params),
        second_auth_manager=second_auth_manager,
        access_control=bool(args.access_control),
        ffuf_wordlist_dir=args.ffuf_wordlist_dir,
        ffuf_api_wordlist=args.ffuf_api_sweep,
        oob_listen=args.oob_listen,
        oob_callback_host=args.oob_callback_host,
        oob_grace=args.oob_grace,
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
        # scan as status=failed. A scan that never got past preflight is a
        # failed run, though.
        return 1 if results.get("error") else 0

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
