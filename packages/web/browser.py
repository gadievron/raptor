"""Headless-browser engine (Playwright/Chromium): rendered crawl and
execution-proof XSS.

The static crawler cannot see what JavaScript builds — SPA routes,
dynamically inserted links and forms — and reflection-based XSS
evidence cannot distinguish "the payload appears unescaped" from "the
payload EXECUTED". A real browser closes both gaps: the rendered
crawl collects the post-JS DOM, and the XSS prover injects a canary
whose only observable effect is a JavaScript side-channel write, so a
hit is execution proof, not string matching.

The Playwright Node driver and its browser descendants run inside RAPTOR's
required outer sandbox. Pages are hostile: every page request passes the
origin gate below. The outer network policy restricts TCP destination ports,
not hostnames; origin checks remain an application-layer defence. Chromium's
own process sandbox is enabled by default. Its explicit waiver never disables
the outer filesystem/process boundary.

The outbound proxy environment (HTTPS_PROXY/HTTP_PROXY/NO_PROXY) is
passed through explicitly: Chromium ignores proxy env vars unless told,
which would silently break proxied deployments while working on
loopback fixtures.

Known fidelity limit of the redirect-consuming gate: the renderer
receives the final response under the ORIGINAL request URL, so the
document base of a post-redirect page is the pre-redirect path and
relative links there may resolve against the wrong directory. That is
the cost of never letting the renderer see a 3xx (which it would
follow ungated); it degrades crawl coverage, never scope.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Any
from contextlib import AbstractContextManager
from urllib.parse import urlparse, urlsplit, urlunsplit

from core.logging import get_logger

from packages.web.origin import origin_of

logger = get_logger()

_DEFAULT_TIMEOUT_MS = 10_000
_SETTLE_MS = 350


def _launch_options(*, allow_unsandboxed_chromium=False) -> dict[str, Any]:
    if type(allow_unsandboxed_chromium) is not bool:
        raise TypeError("allow_unsandboxed_chromium must be a bool")
    # Browser.getBrowserCommandLine requires this flag on supported Chromium builds.
    options: dict[str, Any] = {"headless": True, "chromium_sandbox": not allow_unsandboxed_chromium,
                               "args": ["--enable-automation"]}
    executable = os.environ.get("RAPTOR_WEB_BROWSER_EXECUTABLE")
    if executable:
        if not os.path.isabs(executable):
            raise ValueError("RAPTOR_WEB_BROWSER_EXECUTABLE must be an absolute path")
        options["executable_path"] = executable
    return options


def browser_available(*, base_url="https://browser-probe.invalid", allow_unsandboxed_chromium=False) -> bool:
    """Probe the same confined path used for scans; never retry weaker."""
    try:
        with BrowserEngine(base_url, allow_unsandboxed_chromium=allow_unsandboxed_chromium):
            pass
        return True
    except Exception as error:
        from core.security.log_sanitisation import sanitise_for_terminal
        from core.security.redaction import redact_secrets
        reason = redact_secrets(str(error))
        if len(reason) > 4000:
            reason = reason[:1000] + "\n...\n" + reason[-3000:]
        logger.warning("Browser unavailable under required RAPTOR containment: %s",
                       sanitise_for_terminal(reason, max_len=32768))
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
        allow_unsandboxed_chromium: bool = False,
    ) -> None:
        self._launch_kwargs = _launch_options(allow_unsandboxed_chromium=allow_unsandboxed_chromium)
        self._driver_scope: AbstractContextManager[Any] | None = None
        self._origin = self._normalized_origin(base_url)
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
        # Hosts the gate refused (bounded): blocked-attempt records are
        # evidence in their own right — a poisoned page whose generated
        # markup references an attacker-controllable host proves the
        # generation without letting a single byte leave.
        self._blocked_hosts: list[str] = []

    # -- lifecycle -----------------------------------------------------

    def __enter__(self) -> "BrowserEngine":
        from playwright.sync_api import sync_playwright

        from packages.web._browser_sandbox import confined_driver, require_inner_sandbox_compatibility
        require_inner_sandbox_compatibility(self._launch_kwargs["chromium_sandbox"])
        launch_kwargs = dict(self._launch_kwargs)
        proxy = self._proxy_settings()
        if proxy:
            launch_kwargs["proxy"] = proxy
        self._driver_scope = confined_driver(self._base_url, launch_kwargs.get("executable_path"), proxy)
        try:
            start = self._driver_scope.__enter__()
            self._pw = start(sync_playwright)
            if not launch_kwargs["chromium_sandbox"]:
                logger.warning("Chromium sandbox explicitly disabled; RAPTOR outer containment remains required")
            self._browser = self._pw.chromium.launch(**launch_kwargs)
            if launch_kwargs["chromium_sandbox"]:
                cdp = self._browser.new_browser_cdp_session()
                try:
                    arguments = cdp.send("Browser.getBrowserCommandLine").get("arguments")
                    if not isinstance(arguments, list) or not all(isinstance(arg, str) for arg in arguments):
                        raise RuntimeError("Cannot verify Chromium sandbox launch arguments")
                    if any(arg.split("=", 1)[0] == "--no-sandbox" or
                           (arg.startswith("--disable-") and arg.split("=", 1)[0].endswith("-sandbox"))
                           for arg in arguments):
                        raise RuntimeError("Chromium runtime disabled its sandbox despite the required launch policy")
                finally:
                    cdp.detach()
            # service_workers="block": a worker's fetches bypass page-level
            # routing; nothing the scan renders needs one.
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                service_workers="block",
            )
            self._context.set_default_timeout(self._timeout_ms)
            self._context.route("**/*", self._route_gate)
            # WebSocket connections never enter context.route — gate them
            # separately: same-origin sockets proxy through to the target,
            # off-origin sockets never connect anywhere.
            self._context.route_web_socket("**/*", self._websocket_gate)
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
        except BaseException:
            self.__exit__()
            raise

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
        if self._driver_scope is not None:
            self._driver_scope.__exit__(None, None, None)
            self._driver_scope = None

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

    @staticmethod
    def _normalized_origin(
        url: str, *, scheme_map: dict | None = None,
    ) -> tuple[str, str, int]:
        """(scheme, hostname, port) with default ports normalized.

        Chromium emits WHATWG-normalized request URLs (default port
        removed), so comparing raw netlocs against an operator base_url
        carrying an explicit default port ('http://host:80') mismatched
        on every request and silently aborted the whole browser phase.
        """
        return origin_of(url, scheme_map=scheme_map)

    def _same_origin(self, url: str, *, scheme_map: dict | None = None) -> bool:
        return self._normalized_origin(url, scheme_map=scheme_map) == self._origin

    _MAX_REDIRECT_HOPS = 5

    def _target_request_headers(self, request: Any, url: str) -> dict[str, str]:
        """Rebuild target headers and cookies for a gated Playwright fetch."""
        headers = {
            name.lower(): value for name, value in request.headers.items()
            if name.lower() not in ("host", "content-length", "cookie")
        }
        headers.update({name.lower(): value for name, value in self._extra_headers.items()})
        cookies = self._context.cookies(url)
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{cookie['name']}={cookie['value']}" for cookie in cookies
            )
        return headers

    def _route_gate(self, route: Any) -> None:
        """Origin-gate every request INCLUDING redirect hops.

        Chromium follows redirects internally in two ways this gate
        would never see again: continue_() lets the network stack
        follow them, and even fulfilling a raw 3xx makes the renderer
        follow the Location without a fresh interceptable request
        (verified against a live fixture). So the gate consumes
        redirects itself — fetch with following disabled, walk the
        Location chain manually with an origin check per hop, and hand
        the renderer only the final non-redirect response.
        """
        from urllib.parse import urljoin

        if not self._same_origin(route.request.url):
            self._blocked_requests += 1
            self._note_blocked(route.request.url)
            route.abort()
            return
        response = None
        try:
            response = self._context.request.fetch(
                route.request.url, method=route.request.method,
                data=route.request.post_data_buffer,
                headers=self._target_request_headers(route.request, route.request.url),
                max_redirects=0,
            )
            current_url = route.request.url
            hops = 0
            while 300 <= response.status < 400:
                location = response.headers.get("location")
                if not location:
                    break
                target = urljoin(current_url, location)
                hops += 1
                if hops > self._MAX_REDIRECT_HOPS or not self._same_origin(
                    target,
                ):
                    self._blocked_requests += 1
                    # Record the blocked hop destination too: without
                    # it the blocked_hosts diff was blind to poisoned
                    # markup delivered via a same-origin request whose
                    # redirect CHAIN pivoted off-origin.
                    self._note_blocked(target)
                    route.abort()
                    return
                hop_headers = self._target_request_headers(route.request, target)
                previous_response = response
                if response.status in (307, 308):
                    # Method/body-preserving redirects: replay the
                    # original request shape (headers included — the
                    # content type must survive or form posts arrive
                    # as octet-stream) at the new URL.
                    response = self._context.request.fetch(
                        target,
                        method=route.request.method,
                        data=route.request.post_data_buffer,
                        headers=hop_headers,
                        max_redirects=0,
                    )
                else:
                    hop_headers.pop("content-type", None)
                    response = self._context.request.get(
                        target, headers=hop_headers, max_redirects=0,
                    )
                previous_response.dispose()
                current_url = target
            route.fulfill(response=response)
        except Exception:
            logger.debug("gated fetch failed", exc_info=True)
            try:
                route.abort()
            except Exception:
                logger.debug("route abort failed", exc_info=True)
        finally:
            if response is not None:
                response.dispose()

    def _websocket_gate(self, ws_route: Any) -> None:
        # ws/wss map onto the http/https origin for the compare.
        if self._same_origin(
            ws_route.url, scheme_map={"ws": "http", "wss": "https"},
        ):
            ws_route.connect_to_server()
            return
        # NOT calling connect_to_server() leaves the page-side socket
        # attached to a dead-end mock: nothing ever connects out.
        # (close() here would deadlock — the sync handler runs on the
        # event loop that close() needs to make progress.)
        self._blocked_requests += 1
        self._note_blocked(ws_route.url)

    def _note_blocked(self, url: str) -> None:
        if len(self._blocked_hosts) >= 256:
            return
        host = urlparse(url).netloc.lower()
        if host and host not in self._blocked_hosts:
            self._blocked_hosts.append(host)

    @property
    def blocked_requests(self) -> int:
        return self._blocked_requests

    @property
    def blocked_hosts(self) -> list[str]:
        return list(self._blocked_hosts)

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
