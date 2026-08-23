"""Headless-browser engine (Playwright/Chromium): rendered crawl and
execution-proof XSS.

The static crawler cannot see what JavaScript builds — SPA routes,
dynamically inserted links and forms — and reflection-based XSS
evidence cannot distinguish "the payload appears unescaped" from "the
payload EXECUTED". A real browser closes both gaps: the rendered
crawl collects the post-JS DOM, and the XSS prover injects a canary
whose only observable effect is a JavaScript side-channel write, so a
hit is execution proof, not string matching.

Scope discipline: the browser is the scan's own process tree (like the
OOB listener — trusted code, not a sandboxed external tool), but the
PAGES it renders are hostile. Every request a page makes — navigation,
subresource, XHR — passes a routing gate that aborts anything
off-origin, so a hostile page cannot use the browser as an egress
vehicle or a cross-origin probe. JavaScript executes (that is the
point); its network reach ends at the target origin. Chromium's own
process sandbox stays ON — if the host cannot support it, the engine
reports unavailable rather than degrading isolation for hostile
content.

The outbound proxy environment (HTTPS_PROXY/HTTP_PROXY/NO_PROXY) is
passed through explicitly: Chromium ignores proxy env vars unless told,
which would silently break proxied deployments while working on
loopback fixtures.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from core.logging import get_logger

logger = get_logger()

_DEFAULT_TIMEOUT_MS = 10_000
_SETTLE_MS = 350


def browser_available() -> bool:
    """True when playwright + a launchable Chromium are present."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception as e:
        logger.debug("browser engine unavailable: %s", e)
        return False


@dataclass
class RenderedPage:
    """Post-JavaScript view of one page."""

    url: str
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class XssExecutionProof:
    """A canary that ran inside the page — not a reflection match."""

    url: str
    parameter: str          # query parameter name, or "#fragment"
    payload: str
    tokens: list[str]
    screenshot: str | None = None


class BrowserEngine:
    """Context-managed Chromium wrapper, origin-gated."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_ms: int = _DEFAULT_TIMEOUT_MS,
        screenshots_dir: Any = None,
        cookies: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self._base_url = base_url.rstrip("/")
        self._timeout_ms = timeout_ms
        self._screenshots_dir = screenshots_dir
        self._cookies = dict(cookies or {})
        self._extra_headers = dict(extra_headers or {})
        # playwright objects typed Any: the dependency is optional and
        # import-guarded, so its types can't appear in annotations.
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._blocked_requests = 0

    # -- lifecycle -----------------------------------------------------

    def __enter__(self) -> "BrowserEngine":
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        launch_kwargs: dict[str, Any] = {"headless": True}
        proxy = self._proxy_settings()
        if proxy:
            launch_kwargs["proxy"] = proxy
        self._browser = self._pw.chromium.launch(**launch_kwargs)
        self._context = self._browser.new_context(ignore_https_errors=True)
        self._context.set_default_timeout(self._timeout_ms)
        self._context.route("**/*", self._route_gate)
        if self._extra_headers:
            self._context.set_extra_http_headers(self._extra_headers)
        if self._cookies:
            parsed = urlparse(self._base_url)
            self._context.add_cookies([
                {
                    "name": name,
                    "value": value,
                    "domain": parsed.hostname or "",
                    "path": "/",
                }
                for name, value in self._cookies.items()
            ])
        return self

    def __exit__(self, *_exc: object) -> None:
        for closer in (self._context, self._browser):
            try:
                if closer is not None:
                    closer.close()
            except Exception:
                logger.debug("browser close failed", exc_info=True)
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:
            logger.debug("playwright stop failed", exc_info=True)
        self._pw = self._browser = self._context = None

    @staticmethod
    def _proxy_settings() -> dict[str, str] | None:
        server = (
            os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        )
        if not server:
            return None
        proxy: dict[str, str] = {"server": server}
        bypass = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
        if bypass:
            proxy["bypass"] = bypass
        return proxy

    # -- scope gate ------------------------------------------------------

    def _same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return (parsed.scheme.lower(), parsed.netloc.lower()) == self._origin

    def _route_gate(self, route: Any) -> None:
        if self._same_origin(route.request.url):
            route.continue_()
            return
        self._blocked_requests += 1
        route.abort()

    @property
    def blocked_requests(self) -> int:
        return self._blocked_requests

    # -- rendered crawl ----------------------------------------------------

    def render(self, url: str) -> RenderedPage | None:
        """The post-JS DOM view of one same-origin page."""
        if self._context is None:
            msg = "BrowserEngine used outside its context manager"
            raise RuntimeError(msg)
        if not self._same_origin(url):
            logger.debug("browser render refused off-origin url")
            return None
        page = self._context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(_SETTLE_MS)
            raw = page.evaluate(
                """() => ({
                    links: Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href),
                    forms: Array.from(document.querySelectorAll('form'))
                        .map(f => ({
                            action: f.action || '',
                            method: (f.method || 'GET').toUpperCase(),
                            inputs: Array.from(
                                f.querySelectorAll('input,select,textarea')
                            ).map(i => ({
                                name: i.name || '',
                                type: i.type || 'text',
                            })),
                        })),
                })"""
            )
        except Exception as e:
            logger.debug("browser render failed: %s", e)
            return None
        finally:
            page.close()
        links = [
            link for link in raw.get("links", [])
            if isinstance(link, str) and self._same_origin(link)
        ]
        forms = [
            {
                "action": form.get("action") or url,
                "method": str(form.get("method") or "GET"),
                "inputs": {
                    str(inp.get("name")): {"type": str(inp.get("type") or "text")}
                    for inp in form.get("inputs", [])
                    if inp.get("name")
                },
            }
            for form in raw.get("forms", [])
            if isinstance(form, dict)
        ]
        return RenderedPage(url=url, links=links, forms=forms)

    def rendered_crawl(
        self, urls: list[str], *, max_pages: int = 10,
    ) -> list[RenderedPage]:
        pages = []
        for url in urls[:max_pages]:
            rendered = self.render(url)
            if rendered is not None:
                pages.append(rendered)
        return pages

    # -- execution-proof XSS -------------------------------------------------

    def prove_xss(
        self, url: str, parameter: str | None = None,
    ) -> XssExecutionProof | None:
        """Execution proof: a canary payload whose only effect is a JS
        side-channel write.

        With ``parameter`` set, the payload rides that query parameter
        (reflected-XSS shape). Without it, the payload rides the URL
        fragment (DOM-XSS shape — the fragment never reaches the server,
        so a hit proves a client-side sink). A returned proof means the
        injected JavaScript RAN; reflection without execution returns
        None.
        """
        if self._context is None:
            msg = "BrowserEngine used outside its context manager"
            raise RuntimeError(msg)
        token = f"raptorxss{secrets.token_hex(6)}"
        payload = (
            f"<img src=x onerror=\"window.__raptor_hits.push('{token}')\">"
        )
        scheme, netloc, path, query, _ = urlsplit(url)
        if parameter:
            from urllib.parse import parse_qsl, urlencode
            pairs = [
                (key, value) for key, value in parse_qsl(query)
                if key != parameter
            ]
            pairs.append((parameter, payload))
            target = urlunsplit((scheme, netloc, path, urlencode(pairs), ""))
        else:
            from urllib.parse import quote
            target = urlunsplit(
                (scheme, netloc, path, query, ""),
            ) + "#" + quote(payload)
        if not self._same_origin(target):
            return None

        page = self._context.new_page()
        try:
            page.add_init_script(
                "window.__raptor_hits = window.__raptor_hits || [];"
            )
            page.goto(target, wait_until="domcontentloaded")
            page.wait_for_timeout(_SETTLE_MS)
            hits = page.evaluate("() => window.__raptor_hits || []")
            if token not in hits:
                return None
            screenshot_path: str | None = None
            if self._screenshots_dir is not None:
                from pathlib import Path
                shot = Path(self._screenshots_dir) / f"xss-{token}.png"
                try:
                    page.screenshot(path=str(shot))
                    screenshot_path = str(shot)
                except Exception:
                    logger.debug("xss screenshot failed", exc_info=True)
            return XssExecutionProof(
                url=url,
                parameter=parameter or "#fragment",
                payload=payload,
                tokens=[token],
                screenshot=screenshot_path,
            )
        except Exception as e:
            logger.debug("browser xss probe failed: %s", e)
            return None
        finally:
            page.close()
