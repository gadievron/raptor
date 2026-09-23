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
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs

# No sys.path mutation here: this module is only ever imported (no
# __main__ entry point), and the path-safety rule (CLAUDE.md) forbids
# positional-walk inserts — callers already run with the repo root on
# sys.path via the launcher's RAPTOR_DIR.

from core.logging import get_logger
from core.security.redaction import is_secret_field_name, redact_url_secrets_only
from packages.web.client import WebClient

logger = get_logger()

_SENSITIVE_HIDDEN_INPUT_NAMES = {"csrf", "nonce", "state"}

# Cap on HTML body fed to bs4. Defence in depth above the
# WebClient response-cap layer. 16 MiB is generous for legitimate
# HTML (typical pages <1 MiB) and catches the catastrophic shapes
# (multi-GiB documents, billion-nested-<div>) that OOM bs4.
_BS4_MAX_BYTES = 16 * 1024 * 1024

# Caps on RETAINED discovery state. `max_pages` bounds visits and
# `_BS4_MAX_BYTES` bounds one parse, but neither bounds what a single
# hostile/pathological page (500k anchors fits in 16 MiB) inflates
# into discovered_urls / discovered_parameters / parameter_urls —
# state that consumers then re-materialise (crawl artifacts, research-
# landscape stringification). Raising a cap admits more of a huge site
# into fuzz-cell candidacy at a memory/artifact cost; lowering it
# starves discovery on legitimately large sites — these values keep
# multi-GB inflation out while staying far above what the downstream
# fuzz budgets can consume. Truncation warns once per kind per crawl.
_MAX_DISCOVERED_URLS = 10_000
_MAX_DISCOVERED_PARAMS = 2_000
_MAX_PARAM_URL_FANOUT = 200
_MAX_LINKS_PER_PAGE = 2_000
_MAX_LOG_PAGE_IDS = 10_000


class WebCrawler:
    """Intelligent web crawler with LLM-guided discovery."""

    def __init__(self, client: WebClient, max_depth: int = 3, max_pages: int = 100) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages

        # Discovered resources
        self.visited_urls: set[str] = set()
        self.discovered_urls: set[str] = set()
        self.discovered_forms: list[dict] = []
        # Shape keys of already-recorded forms. A site-wide nav/search/
        # login form repeats on every crawled page; without dedup those
        # byte-identical duplicates fill the scanner's fixed Phase 6
        # form budget and every OTHER form on the site is silently
        # never fuzzed.
        self._seen_form_keys: set[tuple] = set()
        self.discovered_apis: list[dict] = []
        self.discovered_parameters: set[str] = set()
        # param name -> set of (unredacted) URLs whose query string
        # carried it. Lets the scanner fuzz a parameter only where it
        # was actually discovered instead of the full URL x parameter
        # cross-product. Form input names are NOT recorded here — the
        # scanner's form loop fuzzes those against their form action.
        self.parameter_urls: dict[str, set[str]] = {}
        self._log_page_ids: dict[str, str] = {}
        # URLs already placed on the BFS queue: the enqueue check used
        # to dedup only against visited_urls, so a page linking one URL
        # many times (or many pages linking the same URL) grew the
        # queue without bound before any of them was popped.
        self._enqueued_urls: set[str] = set()
        # Once-per-kind truncation warnings — loud, but not per-item.
        self._truncation_warned: set[str] = set()

        logger.info(
            "Web crawler initialized (max_depth=%s, max_pages=%s)", max_depth, max_pages
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
            if len(self._log_page_ids) >= _MAX_LOG_PAGE_IDS:
                # The label map is log furniture; a hostile URL flood
                # must not grow it without bound.
                return f"{self._target_log_label()} page_id=page-overflow"
            page_id = f"page-{len(self._log_page_ids) + 1:04d}"
            self._log_page_ids[raw_url] = page_id
        return f"{self._target_log_label()} page_id={page_id}"

    def _warn_truncation(self, kind: str, cap: int) -> None:
        """One loud warning per truncated discovery structure per crawl."""
        if kind in self._truncation_warned:
            return
        self._truncation_warned.add(kind)
        logger.warning(
            "WebCrawler: %s reached its retention cap (%d) — further "
            "discoveries of this kind are dropped for this crawl",
            kind, cap,
        )

    def _record_discovered_url(self, absolute_url: str) -> bool:
        """Record a discovered URL under the retention cap.

        Returns whether the URL is retained (already known counts)."""
        if absolute_url in self.discovered_urls:
            return True
        if len(self.discovered_urls) >= _MAX_DISCOVERED_URLS:
            self._warn_truncation("discovered_urls", _MAX_DISCOVERED_URLS)
            return False
        self.discovered_urls.add(absolute_url)
        return True

    def _record_parameter(self, name: str, url: str | None = None) -> None:
        """Record a discovered parameter (and its carrying URL) capped."""
        if name not in self.discovered_parameters:
            if len(self.discovered_parameters) >= _MAX_DISCOVERED_PARAMS:
                self._warn_truncation(
                    "discovered_parameters", _MAX_DISCOVERED_PARAMS,
                )
                return
            self.discovered_parameters.add(name)
        if url is None:
            return
        urls = self.parameter_urls.setdefault(name, set())
        if url in urls:
            return
        if len(urls) >= _MAX_PARAM_URL_FANOUT:
            self._warn_truncation(
                "parameter_urls fanout", _MAX_PARAM_URL_FANOUT,
            )
            return
        urls.add(url)

    def _enqueue(self, queue, url: str, depth: int) -> None:
        """Queue a URL for the BFS exactly once per crawl."""
        if queue is None:
            return
        if url in self.visited_urls or url in self._enqueued_urls:
            return
        self._enqueued_urls.add(url)
        queue.append((url, depth))

    def _redacted_url_list(self, urls: set[str]) -> list[str]:
        """Return a deterministic, redacted URL list for persisted crawl artifacts."""
        return [self._redact_url_for_artifact(url) for url in sorted(urls)]

    def _is_sensitive_form_input(self, name: object, metadata: object) -> bool:
        """Return whether a parsed form input value should be hidden in artifacts."""
        if is_secret_field_name(name):
            return True
        if not isinstance(metadata, dict):
            return False
        input_type = str(metadata.get("type", "")).strip().lower()
        if input_type == "password":
            return True
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

    def _redacted_form(self, form: dict) -> dict:
        """Redact sensitive fields from a discovered form artifact."""
        redacted = dict(form)
        for field in ("action", "page_url"):
            if field in redacted:
                redacted[field] = self._redact_url_for_artifact(redacted[field])
        if "inputs" in redacted:
            redacted["inputs"] = self._redacted_form_inputs(redacted["inputs"])
        return redacted

    def _redacted_api(self, api: dict) -> dict:
        """Redact URL-bearing fields from a discovered API artifact."""
        redacted = dict(api)
        if "url" in redacted:
            redacted["url"] = self._redact_url_for_artifact(redacted["url"])
        return redacted

    def crawl(self, start_url: str, seeds: list[str] | None = None) -> dict:
        """
        Crawl website starting from URL.

        ``seeds`` are additional URLs (external discovery, sitemap,
        robots surface) enqueued as real crawl work at depth 1 — merely
        adding them to ``discovered_urls`` would record them without
        ever fetching them, so their forms, links, and parameters would
        never be extracted. Out-of-scope seeds are dropped.

        Returns:
            Dict with discovered resources
        """
        logger.info("Starting crawl from %s", self._crawl_log_label(start_url))

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
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        for seed in seeds or []:
            seed_url = urldefrag(str(seed))[0]
            if not seed_url or seed_url == start_url:
                continue
            try:
                in_scope = self.client._is_in_scope(seed_url)
            except Exception:
                in_scope = False
            if in_scope:
                self._record_discovered_url(seed_url)
                self._enqueue(queue, seed_url, 1)
        while queue:
            if len(self.visited_urls) >= self.max_pages:
                logger.info("Max pages limit reached (%d)", self.max_pages)
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
            logger.debug("Max depth reached for %s", self._crawl_log_label(url))
            return

        if len(self.visited_urls) >= self.max_pages:
            logger.info("Max pages limit reached (%d)", self.max_pages)
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logger.info(
            "Crawling: %s (depth=%s, pages=%s)", self._crawl_log_label(url), depth, len(self.visited_urls)
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
            # mode: any absolute discovered link was silently refetched
            # as `<base_url>/<its path>` — wrong resource on the wrong
            # origin — while the client's scope check (strict
            # scheme+host+port equality; sub-hosts are ALWAYS out of
            # scope) never got to see, and reject, the real off-origin
            # URL.
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
                    "Non-200 response for %s: %s", self._crawl_log_label(url), response.status_code
                )
                return

            # Parse content
            content_type = response.headers.get("Content-Type", "")

            if "application/json" in content_type:
                self._process_json_response(url, response)
            elif "text/html" in content_type:
                self._process_html_response(url, response, depth, _queue=_queue)
            else:
                logger.debug("Skipping non-HTML/JSON content: %s", content_type)

        except Exception as e:
            logger.warning(
                "Error crawling %s: %s", self._crawl_log_label(url), type(e).__name__
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

            # Cap the body before handing to bs4. Without this an in-
            # scope but misbehaving / hostile server can serve a
            # multi-GiB document or a billion-nested-<div> tree and
            # OOM the crawler during DOM construction. WebClient's
            # _enforce_response_cap already bounds the buffered body
            # at _MAX_RESPONSE_BYTES; this is defence in depth for
            # crawler-direct response objects (e.g. test fixtures
            # that bypass the WebClient cap layer).
            body = response.content
            if len(body) > _BS4_MAX_BYTES:
                logger.warning(
                    "WebCrawler: truncating %s body from %d to %d bytes "
                    "before bs4 parse",
                    self._crawl_log_label(url),
                    len(body),
                    _BS4_MAX_BYTES,
                )
                body = body[:_BS4_MAX_BYTES]
            soup = BeautifulSoup(body, "html.parser")

            # Discover links. Per-page cap: one hostile page can carry
            # hundreds of thousands of anchors inside the 16 MiB parse
            # cap; nothing downstream can consume more than this many
            # from a single page.
            page_links = 0
            for link in soup.find_all("a", href=True):
                if page_links >= _MAX_LINKS_PER_PAGE:
                    self._warn_truncation(
                        "per-page links", _MAX_LINKS_PER_PAGE,
                    )
                    break
                href = link["href"]
                if not isinstance(href, str):
                    continue
                # Strip the fragment: it never reaches the wire, so
                # every #anchor of a page is the same resource. Exact-
                # string visited/enqueue checks would otherwise re-fetch
                # an anchor-heavy page once per anchor, burning the
                # max_pages budget on duplicates.
                absolute_url = urldefrag(urljoin(url, href))[0]
                if not absolute_url:
                    continue

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
                #
                # Use the client's _is_in_scope which compares
                # (scheme, hostname, port) — bare netloc carries
                # userinfo + port and mis-compares
                # ``http://base.com`` (port-less) against
                # ``http://base.com:80`` (port-equal-but-explicit),
                # and silently passes ``http://base.com`` JS-
                # discovered downgrades when base is ``https://``.
                if self.client._is_in_scope(absolute_url):
                    page_links += 1
                    if not self._record_discovered_url(absolute_url):
                        continue

                    # Extract parameters from URL
                    parsed = urlparse(absolute_url)
                    if parsed.query:
                        for param_name in parse_qs(parsed.query):
                            self._record_parameter(
                                param_name, absolute_url,
                            )

                    # Enqueue for the BFS loop (or fall through
                    # if no queue — legacy single-page caller).
                    self._enqueue(_queue, absolute_url, depth + 1)

            # Discover forms — dedup by (action, method, field names,
            # hidden-value fingerprint): the same form rendered on many
            # pages is ONE fuzz target, but two forms distinguished only
            # by hidden VALUES (mode=delete vs mode=upload) are distinct
            # handlers and must both survive. Visible-field values stay
            # out of the key (user-fillable variance must not defeat the
            # dedup), and so do anti-forgery hidden values (csrf/nonce/
            # state and secret-named fields rotate per page — keying on
            # them would reopen the budget exhaustion on exactly the
            # site-wide CSRF-protected form the dedup exists for).
            for form in soup.find_all("form"):
                form_data = self._parse_form(form, url)
                if form_data:
                    key = (
                        form_data["action"],
                        form_data["method"],
                        tuple(sorted(form_data["inputs"])),
                        self._hidden_value_fingerprint(form_data["inputs"]),
                    )
                    if key not in self._seen_form_keys:
                        self._seen_form_keys.add(key)
                        self.discovered_forms.append(form_data)
                    for input_name in form_data["inputs"]:
                        self._record_parameter(input_name)

            # Discover API endpoints from JavaScript
            for script in soup.find_all("script"):
                if script.string:
                    self._extract_api_endpoints_from_js(
                        script.string, depth=depth, _queue=_queue,
                    )

        except Exception as e:
            logger.warning(
                "Error parsing HTML from %s: %s", self._crawl_log_label(url), type(e).__name__
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
            logger.info("Discovered API endpoint: %s", self._crawl_log_label(url))
        except Exception as e:
            logger.debug(
                "Error parsing JSON from %s: %s",
                self._crawl_log_label(url), type(e).__name__
            )

    def _hidden_value_fingerprint(
        self, inputs: dict,
    ) -> tuple[tuple[str, str], ...]:
        """Sorted (name, value) pairs of the DISCRIMINATING hidden inputs.

        Hidden values are the only place two same-shaped forms can
        differ in what handler they reach (mode=delete vs mode=upload),
        so they join the dedup key — except anti-forgery material
        (csrf/nonce/state and secret-named fields, via the same
        classifier the artifact redaction uses): those rotate per page
        and would make every copy of a CSRF-protected form look unique.
        """
        pairs = []
        for name, metadata in inputs.items():
            meta = metadata if isinstance(metadata, dict) else {}
            if str(meta.get("type", "")).strip().lower() != "hidden":
                continue
            if self._is_sensitive_form_input(name, meta):
                continue
            pairs.append((str(name), str(meta.get("value", ""))))
        return tuple(sorted(pairs))

    # The only methods an HTML form can submit with; anything else in
    # the attribute (per the HTML spec, and per hostile pages — bs4
    # entity-decodes `&#10;` into a live newline that would ride the
    # discovered method into downstream artifacts) is invalid and
    # defaults to GET.
    _FORM_METHODS = frozenset({"GET", "POST"})

    def _parse_form(self, form_element, page_url: str) -> dict | None:
        """Parse HTML form to extract inputs and action."""
        try:
            action = form_element.get("action", "")
            method = str(form_element.get("method", "GET") or "GET").strip().upper()
            if method not in self._FORM_METHODS:
                method = "GET"
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
            logger.debug("Error parsing form: %s", type(e).__name__)
            return None

    def _extract_api_endpoints_from_js(self, js_code: str, *,
                                       depth: int = 0,
                                       _queue=None) -> None:
        """Extract API endpoints from JavaScript code.

        Discovered endpoints are recorded as API candidates AND
        enqueued for the crawl — they used to land only in
        ``discovered_urls``, so a JS-only endpoint was never fetched,
        never classified as an API, and never contributed parameters:
        a coverage gap for exactly the URLs reachable only through
        script analysis.
        """
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
                "JS body (%s chars) exceeds API-endpoint-scan cap (%s); truncating", len(js_code), _MAX_JS_BYTES
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
                if match.startswith(("/", "http")):
                    # Same fragment-stripping rule as anchor discovery.
                    absolute_url = urldefrag(
                        urljoin(self.client.base_url, match),
                    )[0]
                    # Scheme-aware scope check via client._is_in_scope
                    # — bare netloc equality silently accepted a JS-
                    # discovered ``http://base.com/x`` against a
                    # configured ``https://base.com`` base, since
                    # netloc compares port-less identical and
                    # ignores scheme. _is_in_scope compares the
                    # (scheme, hostname, port) triple.
                    if self.client._is_in_scope(absolute_url):
                        if not self._record_discovered_url(absolute_url):
                            continue
                        # Classify as an API candidate now (static
                        # discovery — no response shape yet; crawling
                        # the URL refines it via
                        # _process_json_response).
                        if not any(a.get("url") == absolute_url
                                   for a in self.discovered_apis):
                            self.discovered_apis.append({
                                "url": absolute_url,
                                "method": "GET",
                                "response_keys": [],
                                "source": "js-static",
                            })
                        self._enqueue(_queue, absolute_url, depth + 1)
                        logger.debug(
                            "Found API endpoint in JS: %s", self._crawl_log_label(absolute_url)
                        )

    def get_results(self) -> dict:
        """Live crawl results — RAW values, for the scan data plane.

        Downstream phases (param mining, fuzz-cell construction,
        verification replays) must probe the URLs the crawler actually
        fetched: redacting here would corrupt the very values the
        probes send (a ``?token=...`` endpoint becomes unfuzzable and
        every derived verification targets a URL that never existed).
        Redaction is a display/persist concern — persisted artifacts go
        through :meth:`artifact_results` (or the scanner's artifact
        redaction boundary) instead.
        """
        return {
            "visited_urls": sorted(self.visited_urls),
            "discovered_urls": sorted(self.discovered_urls),
            "discovered_forms": list(self.discovered_forms),
            "discovered_apis": list(self.discovered_apis),
            "discovered_parameters": sorted(self.discovered_parameters),
            "parameter_urls": {
                param: sorted(urls)
                for param, urls in sorted(self.parameter_urls.items())
            },
            "stats": {
                "total_pages": len(self.visited_urls),
                "total_urls": len(self.discovered_urls),
                "total_forms": len(self.discovered_forms),
                "total_apis": len(self.discovered_apis),
                "total_parameters": len(self.discovered_parameters),
            },
        }

    def artifact_results(self) -> dict:
        """Redacted projection of :meth:`get_results` for persisted
        crawl artifacts (secret-named query values and sensitive form
        input values hidden unless the operator opted into reveal
        mode)."""
        raw = self.get_results()
        return {
            **raw,
            "visited_urls": self._redacted_url_list(self.visited_urls),
            "discovered_urls": self._redacted_url_list(self.discovered_urls),
            "discovered_forms": [
                self._redacted_form(form) for form in self.discovered_forms
            ],
            "discovered_apis": [
                self._redacted_api(api) for api in self.discovered_apis
            ],
            "parameter_urls": {
                param: self._redacted_url_list(urls)
                for param, urls in sorted(self.parameter_urls.items())
            },
        }
