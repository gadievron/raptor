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
        self._crawl_recursive(start_url, depth=0)

        return self.get_results()

    def _crawl_recursive(self, url: str, depth: int) -> None:
        """Recursively crawl pages."""
        if depth > self.max_depth:
            logger.debug(f"Max depth reached for {self._crawl_log_label(url)}")
            return

        if len(self.visited_urls) >= self.max_pages:
            logger.info(f"Max pages limit reached ({self.max_pages})")
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logger.info(
            f"Crawling: {self._crawl_log_label(url)} "
            f"(depth={depth}, pages={len(self.visited_urls)})"
        )

        try:
            # Fetch page
            parsed_url = urlparse(url)
            path = parsed_url.path + (
                f"?{parsed_url.query}" if parsed_url.query else ""
            )
            response = self.client.get(path)

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
                self._process_html_response(url, response, depth)
            else:
                logger.debug(f"Skipping non-HTML/JSON content: {content_type}")

        except Exception as e:
            logger.warning(
                f"Error crawling {self._crawl_log_label(url)}: {type(e).__name__}"
            )

    def _process_html_response(self, url: str, response, depth: int) -> None:
        """Process HTML response to discover links, forms, etc."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(response.content, "html.parser")

            # Discover links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                absolute_url = urljoin(url, href)

                # Only follow links on same domain
                if urlparse(absolute_url).netloc == urlparse(url).netloc:
                    self.discovered_urls.add(absolute_url)

                    # Extract parameters from URL
                    parsed = urlparse(absolute_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        self.discovered_parameters.update(params.keys())

                    # Crawl this URL
                    self._crawl_recursive(absolute_url, depth + 1)

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
        # Look for common patterns
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'["\'](?:api|endpoint)["\']:\s*["\']([^"\']+)["\']',
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
