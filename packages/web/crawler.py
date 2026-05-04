#!/usr/bin/env python3
"""
Intelligent Web Crawler

LLM-powered web crawler that:
- Discovers pages and endpoints
- Identifies input parameters
- Maps application structure
- Finds hidden functionality
"""

import re
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, urljoin, parse_qs

import sys
from pathlib import Path

# Add paths for cross-package imports
# packages/web/crawler.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.logging import get_logger
from core.security.redaction import is_secret_field_name, redact_url_secrets_only
from packages.web.client import WebClient

logger = get_logger()

_SENSITIVE_HIDDEN_INPUT_NAMES = {"csrf", "nonce", "state"}


class WebCrawler:
    """Intelligent web crawler with LLM-guided discovery."""

    def __init__(self, client: WebClient, max_depth: int = 3, max_pages: int = 100):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages

        # Discovered resources
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.discovered_apis: List[Dict] = []
        self.discovered_parameters: Set[str] = set()
        self._log_page_ids: Dict[str, str] = {}

        logger.info(
            f"Web crawler initialized (max_depth={max_depth}, max_pages={max_pages})"
        )

    def _redact_url_for_artifact(self, url: object) -> str:
        """Redact URL-embedded secrets unless the operator opted into reveal mode."""
        return redact_url_secrets_only(url, reveal_secrets=self.client.reveal_secrets)

    def _target_log_label(self) -> str:
        """Return the non-secret crawl target origin for log messages."""
        parsed = urlparse(str(self.client.base_url))
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
        if not host:
            return "target"
        port = f":{parsed.port}" if parsed.port else ""
        return f"{scheme}{host}{port}"

    def _crawl_log_label(self, url: object) -> str:
        """Return a stable non-URL page label for crawler logs.

        CodeQL treats user-controlled URL strings as sensitive logging sinks even
        after query-string redaction. Logs therefore use a per-crawl page ID plus
        the non-secret base origin. Persisted crawl artifacts still retain
        redacted path/query context for operator review.
        """
        raw_url = str(url)
        page_id = self._log_page_ids.get(raw_url)
        if page_id is None:
            page_id = f"page-{len(self._log_page_ids) + 1:04d}"
            self._log_page_ids[raw_url] = page_id
        return f"{self._target_log_label()} page_id={page_id}"

    def _redacted_url_list(self, urls: Set[str]) -> List[str]:
        """Return a deterministic, redacted URL list for persisted crawl artifacts."""
        return [self._redact_url_for_artifact(url) for url in sorted(urls)]

    def _is_sensitive_form_input(self, name: object, metadata: object) -> bool:
        """Return whether a parsed form input value should be hidden in artifacts."""
        if is_secret_field_name(name):
            return True
        if not isinstance(metadata, dict):
            return False
        input_type = str(metadata.get("type", "")).strip().lower()
        normalized_name = str(name).strip().lower()
        return (
            input_type == "hidden" and normalized_name in _SENSITIVE_HIDDEN_INPUT_NAMES
        )

    def _redacted_form_inputs(self, inputs: object) -> object:
        """Redact sensitive pre-filled form input values while preserving shape."""
        if not isinstance(inputs, dict):
            return inputs

        redacted_inputs = {}
        for name, metadata in inputs.items():
            if isinstance(metadata, dict):
                redacted_metadata = dict(metadata)
                if "value" in redacted_metadata:
                    if (
                        self._is_sensitive_form_input(name, metadata)
                        and not self.client.reveal_secrets
                    ):
                        redacted_metadata["value"] = "[REDACTED]"
                    else:
                        redacted_metadata["value"] = self._redact_url_for_artifact(
                            redacted_metadata["value"]
                        )
                redacted_inputs[name] = redacted_metadata
            else:
                redacted_inputs[name] = metadata
        return redacted_inputs

    def _redacted_form(self, form: Dict) -> Dict:
        """Redact sensitive fields from a discovered form artifact."""
        redacted = dict(form)
        for field in ("action", "page_url"):
            if field in redacted:
                redacted[field] = self._redact_url_for_artifact(redacted[field])
        if "inputs" in redacted:
            redacted["inputs"] = self._redacted_form_inputs(redacted["inputs"])
        return redacted

    def _redacted_api(self, api: Dict) -> Dict:
        """Redact URL-bearing fields from a discovered API artifact."""
        redacted = dict(api)
        if "url" in redacted:
            redacted["url"] = self._redact_url_for_artifact(redacted["url"])
        return redacted

    def crawl(self, start_url: str) -> Dict:
        """
        Crawl website starting from URL.

        Returns:
            Dict with discovered resources
        """
        logger.info(f"Starting crawl from {self._crawl_log_label(start_url)}")

        self.discovered_urls.add(start_url)

        # Iterative BFS via an explicit work queue. Pre-fix this
        # called `_crawl_recursive(start_url, depth=0)` which
        # recursed into every discovered child. With Python's
        # default recursion limit of 1000 and a deep linked
        # site (e.g. a paginated forum or doc tree where each
        # page links to the next), the crawl crashed with
        # `RecursionError: maximum recursion depth exceeded`
        # at the worst possible moment — well into a long
        # crawl, with all discovered_* state thrown away on
        # the unwind. Operators saw "web crawl failed
        # mid-run" with no per-URL diagnostic.
        #
        # The recursion-bounding controls (`max_depth=3`,
        # `max_pages=100`) helped under default config, but
        # operators routinely override `--max-depth 10` for
        # exhaustive scans, putting them well into stack-
        # exhaustion territory.
        #
        # Use an explicit FIFO queue. `_crawl_recursive` now
        # acts as a single-page-fetch helper; the BFS loop
        # below drives multiple passes.
        from collections import deque
        queue: "deque[tuple[str, int]]" = deque([(start_url, 0)])
        while queue:
            if len(self.visited_urls) >= self.max_pages:
                logger.info(f"Max pages limit reached ({self.max_pages})")
                break
            url, depth = queue.popleft()
            self._crawl_recursive(url, depth, _queue=queue)

        return self.get_results()

    def _crawl_recursive(self, url: str, depth: int, _queue=None) -> None:
        """Crawl a single page; enqueue discovered child URLs onto _queue.

        Despite the name (preserved for backwards-compat with
        any test that mocks it), this no longer recurses —
        `crawl()` drives the BFS with an explicit work queue
        and calls this once per popped URL. The `_queue`
        kwarg is the BFS queue from `crawl()`; child URLs go
        on it instead of being recursed into. When called
        without `_queue` (legacy callers), the function still
        does the per-page work but doesn't expand further.
        """
        if depth > self.max_depth:
            logger.debug(f"Max depth reached for {self._crawl_log_label(url)}")
            return

        if len(self.visited_urls) >= self.max_pages:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logger.info(
            f"Crawling: {self._crawl_log_label(url)} "
            f"(depth={depth}, pages={len(self.visited_urls)})"
        )

        try:
            # Fetch page. Pre-fix the crawler stripped the URL to
            # path+query only:
            #
            #   parsed_url = urlparse(url)
            #   path = parsed_url.path + (?{query} if query else "")
            #   response = self.client.get(path)
            #
            # That LOST the original host/scheme. WebClient._build_url
            # then `urljoin(base_url + '/', path)` re-anchored every
            # discovered URL onto base_url's host. Concrete failure
            # mode: a discovered link
            # `https://api.example.com/v1/users` (a sub-host the
            # operator wanted in scope, e.g. assets.example.com or
            # api.example.com under the same TARGET) was crawled as
            # `<base_url>/v1/users` — wrong host, hits the wrong
            # service, gets a 404 or worse cross-host data, and the
            # actual sub-host endpoint is NEVER fetched even though
            # the crawler thinks it covered it.
            #
            # Pass the full URL. `WebClient._build_url(url)` does
            # `urljoin(base_url+'/', url)` which preserves the
            # scheme/host when `url` is already absolute, then
            # `_is_in_scope(url)` rejects out-of-origin URLs with
            # ValueError — the crawl-scope check still fires, AND
            # the correct host is hit when the URL is in-scope.
            response = self.client.get(url)

            if response.status_code != 200:
                logger.debug(
                    f"Non-200 response for {self._crawl_log_label(url)}: "
                    f"{response.status_code}"
                )
                return

            # Parse content
            content_type = response.headers.get("Content-Type", "")

            if "application/json" in content_type:
                self._process_json_response(url, response)
            elif "text/html" in content_type:
                self._process_html_response(url, response, depth, _queue=_queue)
            else:
                logger.debug(f"Skipping non-HTML/JSON content: {content_type}")

        except Exception as e:
            logger.warning(
                f"Error crawling {self._crawl_log_label(url)}: {type(e).__name__}"
            )

    def _process_html_response(self, url: str, response, depth: int, _queue=None) -> None:
        """Process HTML response to discover links, forms, etc.

        `_queue` is the BFS work queue from `crawl()`; when
        provided, discovered in-scope URLs go on it for later
        processing instead of being recursed into. None for
        legacy callers (no further crawl, just per-page
        discovery).
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(response.content, "html.parser")

            # Discover links
            base_netloc = urlparse(self.client.base_url).netloc
            for link in soup.find_all("a", href=True):
                href = link["href"]
                absolute_url = urljoin(url, href)

                # Scope-check against `base_url`, not the
                # currently-being-crawled URL. Pre-fix
                # `urlparse(url).netloc` was the comparison —
                # which means once a crawl drifted onto a
                # different host (via an off-target link or a
                # redirect we followed), every subsequent link
                # FROM that off-target page was considered
                # in-scope (matching the off-target's own netloc).
                # The crawler then progressively wandered away
                # from the operator-configured target. Anchor
                # the scope check to base_url instead so drift
                # is bounded to immediate neighbours rather than
                # transitive expansion.
                if urlparse(absolute_url).netloc == base_netloc:
                    self.discovered_urls.add(absolute_url)

                    # Extract parameters from URL
                    parsed = urlparse(absolute_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        self.discovered_parameters.update(params.keys())

                    # Enqueue for the BFS loop (or fall through
                    # if no queue — legacy single-page caller).
                    if _queue is not None and absolute_url not in self.visited_urls:
                        _queue.append((absolute_url, depth + 1))

            # Discover forms
            for form in soup.find_all("form"):
                form_data = self._parse_form(form, url)
                if form_data:
                    self.discovered_forms.append(form_data)
                    self.discovered_parameters.update(form_data["inputs"].keys())

            # Discover API endpoints from JavaScript
            for script in soup.find_all("script"):
                if script.string:
                    self._extract_api_endpoints_from_js(script.string)

        except Exception as e:
            logger.warning(
                f"Error parsing HTML from {self._crawl_log_label(url)}: "
                f"{type(e).__name__}"
            )

    def _process_json_response(self, url: str, response) -> None:
        """Process JSON response (likely API endpoint)."""
        try:
            data = response.json()
            self.discovered_apis.append(
                {
                    "url": url,
                    "method": "GET",
                    "response_keys": list(data.keys())
                    if isinstance(data, dict)
                    else [],
                }
            )
            logger.info(f"Discovered API endpoint: {self._crawl_log_label(url)}")
        except Exception as e:
            logger.debug(
                f"Error parsing JSON from {self._crawl_log_label(url)}: "
                f"{type(e).__name__}"
            )

    def _parse_form(self, form_element, page_url: str) -> Optional[Dict]:
        """Parse HTML form to extract inputs and action."""
        try:
            action = form_element.get("action", "")
            method = form_element.get("method", "GET").upper()
            absolute_action = urljoin(page_url, action)

            inputs = {}
            for input_elem in form_element.find_all(["input", "textarea", "select"]):
                name = input_elem.get("name")
                if name:
                    inputs[name] = {
                        "type": input_elem.get("type", "text"),
                        "value": input_elem.get("value", ""),
                    }

            return {
                "action": absolute_action,
                "method": method,
                "inputs": inputs,
                "page_url": page_url,
            }

        except Exception as e:
            logger.debug(f"Error parsing form: {type(e).__name__}")
            return None

    def _extract_api_endpoints_from_js(self, js_code: str) -> None:
        """Extract API endpoints from JavaScript code."""
        # Cap the JS-code size before per-pattern findall. Pre-fix
        # `re.findall` ran 4 times over the FULL js_code body; for
        # a multi-MB minified bundle (modern frontend SPAs ship
        # 5-20 MB single-file bundles in dev mode) the per-pattern
        # scan accumulated to multi-second wallclock per page.
        # Worse, the per-pattern alternation `[^"\']+` is greedy
        # and unbounded — a hostile JS payload with no closing
        # quote forces backtracking proportional to the bundle
        # size. 4 MB cap leaves headroom for legitimate
        # production bundles while bounding the worst case.
        _MAX_JS_BYTES = 4 * 1024 * 1024
        if len(js_code) > _MAX_JS_BYTES:
            logger.debug(
                f"JS body ({len(js_code)} chars) exceeds API-endpoint-scan "
                f"cap ({_MAX_JS_BYTES}); truncating"
            )
            js_code = js_code[:_MAX_JS_BYTES]

        # Look for common patterns. Each `[^"\']+` is bounded above
        # via the {1,4096} cap — a single URL longer than 4 KB is
        # almost certainly a base64 blob misclassified as a URL,
        # not a real endpoint.
        patterns = [
            r'fetch\(["\']([^"\']{1,4096})["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']{1,4096})["\']',
            r'\.ajax\(\{[^}]{0,4096}url:\s*["\']([^"\']{1,4096})["\']',
            r'["\'](?:api|endpoint)["\']:\s*["\']([^"\']{1,4096})["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if match.startswith("/") or match.startswith("http"):
                    absolute_url = urljoin(self.client.base_url, match)
                    if (
                        urlparse(absolute_url).netloc
                        == urlparse(self.client.base_url).netloc
                    ):
                        self.discovered_urls.add(absolute_url)
                        logger.debug(
                            f"Found API endpoint in JS: {self._crawl_log_label(absolute_url)}"
                        )

    def get_results(self) -> Dict:
        """Get crawl results."""
        return {
            "visited_urls": self._redacted_url_list(self.visited_urls),
            "discovered_urls": self._redacted_url_list(self.discovered_urls),
            "discovered_forms": [
                self._redacted_form(form) for form in self.discovered_forms
            ],
            "discovered_apis": [
                self._redacted_api(api) for api in self.discovered_apis
            ],
            "discovered_parameters": sorted(self.discovered_parameters),
            "stats": {
                "total_pages": len(self.visited_urls),
                "total_urls": len(self.discovered_urls),
                "total_forms": len(self.discovered_forms),
                "total_apis": len(self.discovered_apis),
                "total_parameters": len(self.discovered_parameters),
            },
        }
