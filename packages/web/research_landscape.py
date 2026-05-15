"""Research-driven web testing landscape.

The scanner should track current web research, not just static ASVS checks.
This module turns recurring themes from the PortSwigger Top 10 Web Hacking
Techniques archive into an explicit coverage and prioritisation model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


PORTSWIGGER_ARCHIVE_URL = (
    "https://portswigger.net/research/top-10-web-hacking-techniques"
)


@dataclass(frozen=True)
class ResearchTheme:
    id: str
    title: str
    years: tuple[int, ...]
    sources: tuple[str, ...]
    covered_by: tuple[str, ...]
    signals: tuple[str, ...]
    action: str


RESEARCH_THEMES: tuple[ResearchTheme, ...] = (
    ResearchTheme(
        id="parser_differentials_desync",
        title="Parser differentials, semantic ambiguity, and HTTP desync",
        years=(2025, 2024, 2021, 2020),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2021",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2020",
        ),
        covered_by=("V5.1.14",),
        signals=("proxy", "cdn", "http2", "apache", "nginx", "varnish", "cloudfront"),
        action=(
            "Probe parser boundaries conservatively: CL.TE, TE.0/CL.0 candidates, "
            "hidden header acceptance, HTTP version downgrades, and ambiguous path handling."
        ),
    ),
    ResearchTheme(
        id="cache_poisoning_deception_frameworks",
        title="Web cache poisoning, deception, and framework cache chains",
        years=(2025, 2024, 2021, 2017),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2021",
            PORTSWIGGER_ARCHIVE_URL,
        ),
        covered_by=("V5.1.12", "V5.1.13"),
        signals=("cache", "next", "x-cache", "cf-cache-status", "age", "vary"),
        action=(
            "Map cache indicators, route fallbacks, static suffix handling, unkeyed "
            "header reflection, and framework-specific cache behaviour."
        ),
    ),
    ResearchTheme(
        id="ssrf_redirect_loops_non_http",
        title="SSRF visibility, redirect loops, and non-HTTP backend reachability",
        years=(2025, 2021, 2020),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2021",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2020",
        ),
        covered_by=("V10.3.1", "V10.3.2"),
        signals=("url", "uri", "redirect", "callback", "webhook", "next", "proxy"),
        action=(
            "Prioritise URL-shaped inputs, redirect chains, proxy headers, metadata "
            "targets, and places where blind SSRF can be made observable."
        ),
    ),
    ResearchTheme(
        id="unicode_charset_normalisation",
        title="Unicode, charset conversion, and normalisation abuse",
        years=(2025, 2024),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
        ),
        covered_by=(),
        signals=("charset", "encoding", "unicode", "normalization", "normalisation"),
        action=(
            "Add normalisation probes for auth, routing, upload names, cache keys, "
            "and WAF/application parser disagreements."
        ),
    ),
    ResearchTheme(
        id="browser_side_channels_xsleaks",
        title="Browser side channels, XS-Leaks, and timing oracles",
        years=(2025, 2024),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
        ),
        covered_by=(),
        signals=("etag", "redirect", "cross-origin", "timing", "frame", "cache-control"),
        action=(
            "Add browser-assisted checks for cross-origin redirect leaks, ETag length "
            "leaks, timing differentials, and frame/navigation side channels."
        ),
    ),
    ResearchTheme(
        id="server_side_template_and_error_oracles",
        title="Blind SSTI, code injection, and successful-error oracles",
        years=(2025, 2020),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2020",
        ),
        covered_by=("V5.2.1",),
        signals=("template", "view", "message", "error", "debug", "render"),
        action=(
            "Bias fuzzing toward polyglot SSTI and error-based detection where normal "
            "reflected probes do not produce obvious output."
        ),
    ),
    ResearchTheme(
        id="orm_filter_data_exposure",
        title="ORM, search, join, and filtering data exposure",
        years=(2025, 2024),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
        ),
        covered_by=(),
        signals=("filter", "sort", "include", "join", "fields", "search", "query"),
        action=(
            "Treat rich filtering APIs as data-exfiltration surfaces, not just SQLi "
            "surfaces; compare response shape and joined-object leakage."
        ),
    ),
    ResearchTheme(
        id="oauth_cookie_auth_chains",
        title="OAuth, cookie tossing, SAML, and authentication chain abuse",
        years=(2025, 2024, 2021),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2021",
        ),
        covered_by=("V2.2.1", "V2.2.2", "V3.4.1", "V3.4.2"),
        signals=("oauth", "saml", "oidc", "redirect_uri", "state", "cookie"),
        action=(
            "Map non-happy-path auth flows, cookie scope collisions, redirect_uri "
            "handling, state binding, SAML endpoints, and referer-based redirects."
        ),
    ),
    ResearchTheme(
        id="client_side_sanitizer_and_dom_mutation",
        title="Client-side parser stacks, mXSS, DOM sanitizers, and prototype pollution",
        years=(2024, 2021),
        sources=(
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2024",
            "https://portswigger.net/research/top-10-web-hacking-techniques-of-2021",
        ),
        covered_by=("V5.1.15",),
        signals=("dompurify", "__proto__", "sanitize", "innerhtml", "prototype"),
        action=(
            "Use JS route and bundle discovery to flag sanitizer usage, prototype "
            "pollution sinks, and nested parser contexts for browser-assisted testing."
        ),
    ),
)


def assess_research_landscape(
    *,
    discovery: object,
    crawl_data: dict,
    registered_check_ids: Iterable[str],
) -> dict:
    """Return a target-aware coverage map for current web research themes."""
    registered = set(registered_check_ids)
    signals = _collect_signals(discovery, crawl_data)

    themes = []
    for theme in RESEARCH_THEMES:
        covered = [check_id for check_id in theme.covered_by if check_id in registered]
        matched = [signal for signal in theme.signals if signal in signals]
        if not theme.covered_by:
            coverage = "planned"
        elif len(covered) == len(theme.covered_by):
            coverage = "covered"
        elif covered:
            coverage = "partial"
        else:
            coverage = "gap"

        priority = "high" if matched and coverage in {"partial", "planned", "gap"} else "normal"
        themes.append({
            "id": theme.id,
            "title": theme.title,
            "coverage": coverage,
            "covered_by": covered,
            "missing_checks": [
                check_id for check_id in theme.covered_by if check_id not in registered
            ],
            "top10_years": list(theme.years),
            "sources": list(theme.sources),
            "target_signals": matched,
            "priority": priority,
            "recommended_assessment": theme.action,
        })

    return {
        "source_archive": PORTSWIGGER_ARCHIVE_URL,
        "archive_years_reviewed": list(range(2006, 2026)),
        "curation_mode": "static_versioned_registry",
        "method": (
            "Themes distilled from the PortSwigger Top 10 Web Hacking Techniques "
            "archive and mapped to RAPTOR checks, fuzzing priorities, and target "
            "signals observed during discovery and crawl. Source URLs are provenance "
            "links; scans do not fetch or execute remote research content at runtime."
        ),
        "themes": themes,
    }


def high_priority_theme_ids(research_landscape: dict) -> list[str]:
    return [
        theme["id"]
        for theme in research_landscape.get("themes", [])
        if theme.get("priority") == "high"
    ]


def _collect_signals(discovery: object, crawl_data: dict) -> set[str]:
    signal_text: list[str] = []
    if discovery:
        for attr in (
            "urls", "forms", "apis", "parameters", "fingerprint",
            "common_paths_found", "robots_disallow",
        ):
            signal_text.append(str(getattr(discovery, attr, "")))
    signal_text.append(str(crawl_data.get("discovered_urls", [])))
    signal_text.append(str(crawl_data.get("visited_urls", [])))
    signal_text.append(str(crawl_data.get("discovered_parameters", [])))
    signal_text.append(str(crawl_data.get("discovered_forms", [])))
    haystack = " ".join(signal_text).lower()
    tokens = set(re.findall(r"[a-z0-9_:-]+", haystack))
    tokens.update(token.replace("-", "_") for token in list(tokens))
    return tokens
