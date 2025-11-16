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
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bs4 import BeautifulSoup

from core.logging import get_logger
from .client import WebClient

logger = get_logger()


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

        logger.info(f"Web crawler initialized (max_depth={max_depth}, max_pages={max_pages})")

    def crawl(self, start_url: str) -> Dict:
        """
        Crawl website starting from URL.

        Returns:
            Dict with discovered resources
        """
        logger.info(f"Starting crawl from {start_url}")

        self.discovered_urls.add(start_url)
        self._crawl_recursive(start_url, depth=0)

        return self.get_results()

    def _crawl_recursive(self, url: str, depth: int) -> None:
        """Recursively crawl pages."""
        if depth > self.max_depth:
            logger.debug(f"Max depth reached for {url}")
            return

        if len(self.visited_urls) >= self.max_pages:
            logger.info(f"Max pages limit reached ({self.max_pages})")
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logger.info(f"Crawling: {url} (depth={depth}, pages={len(self.visited_urls)})")

        try:
            # Fetch page
            parsed_url = urlparse(url)
            path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
            response = self.client.get(path)

            if response.status_code != 200:
                logger.debug(f"Non-200 response for {url}: {response.status_code}")
                return

            # Parse content
            content_type = response.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                self._process_json_response(url, response)
            elif 'text/html' in content_type:
                self._process_html_response(url, response, depth)
            else:
                logger.debug(f"Skipping non-HTML/JSON content: {content_type}")

        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")

    def _process_html_response(self, url: str, response, depth: int) -> None:
        """Process HTML response to discover links, forms, etc."""
        try:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Discover links
            for link in soup.find_all('a', href=True):
                href = link['href']
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
            for form in soup.find_all('form'):
                form_data = self._parse_form(form, url)
                if form_data:
                    self.discovered_forms.append(form_data)
                    self.discovered_parameters.update(form_data['inputs'].keys())

            # Discover API endpoints from JavaScript
            for script in soup.find_all('script'):
                if script.string:
                    self._extract_api_endpoints_from_js(script.string)

        except Exception as e:
            logger.warning(f"Error parsing HTML from {url}: {e}")

    def _process_json_response(self, url: str, response) -> None:
        """Process JSON response (likely API endpoint)."""
        try:
            data = response.json()
            self.discovered_apis.append({
                'url': url,
                'method': 'GET',
                'response_keys': list(data.keys()) if isinstance(data, dict) else [],
            })
            logger.info(f"Discovered API endpoint: {url}")
        except Exception as e:
            logger.debug(f"Error parsing JSON from {url}: {e}")

    def _parse_form(self, form_element, page_url: str) -> Optional[Dict]:
        """Parse HTML form to extract inputs and action."""
        try:
            action = form_element.get('action', '')
            method = form_element.get('method', 'GET').upper()
            absolute_action = urljoin(page_url, action)

            inputs = {}
            for input_elem in form_element.find_all(['input', 'textarea', 'select']):
                name = input_elem.get('name')
                if name:
                    inputs[name] = {
                        'type': input_elem.get('type', 'text'),
                        'value': input_elem.get('value', ''),
                    }

            return {
                'action': absolute_action,
                'method': method,
                'inputs': inputs,
                'page_url': page_url,
            }

        except Exception as e:
            logger.debug(f"Error parsing form: {e}")
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
                if match.startswith('/') or match.startswith('http'):
                    absolute_url = urljoin(self.client.base_url, match)
                    if urlparse(absolute_url).netloc == urlparse(self.client.base_url).netloc:
                        self.discovered_urls.add(absolute_url)
                        logger.debug(f"Found API endpoint in JS: {absolute_url}")

    def get_results(self) -> Dict:
        """Get crawl results."""
        return {
            'visited_urls': list(self.visited_urls),
            'discovered_urls': list(self.discovered_urls),
            'discovered_forms': self.discovered_forms,
            'discovered_apis': self.discovered_apis,
            'discovered_parameters': list(self.discovered_parameters),
            'stats': {
                'total_pages': len(self.visited_urls),
                'total_urls': len(self.discovered_urls),
                'total_forms': len(self.discovered_forms),
                'total_apis': len(self.discovered_apis),
                'total_parameters': len(self.discovered_parameters),
            },
        }
