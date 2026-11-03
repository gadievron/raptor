#!/usr/bin/env python3
"""Check the published container's system browser with an offline page."""
import argparse
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright


def check_basic() -> None:
    executable = os.environ.get("RAPTOR_WEB_BROWSER_EXECUTABLE")
    if executable != "/usr/bin/chromium":
        raise ValueError("container browser must select /usr/bin/chromium")
    if not Path("/usr/share/doc/chromium/copyright").is_file():
        raise ValueError("Chromium package copyright inventory is missing")
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable, headless=True)
        try:
            page = browser.new_page(service_workers="block")
            page.route("**/*", lambda route: route.abort())
            page.set_content('<title>Browser check</title><button onclick="this.textContent=42">Run</button>')
            page.get_by_role("button").click()
            if page.title() != "Browser check" or page.get_by_role("button").inner_text() != "42":
                raise ValueError("offline browser interaction failed")
            print("Chromium offline check passed:", browser.version)
        finally:
            browser.close()


@contextmanager
def disposable_environment(root):
    """Use only test-owned state, restoring the caller's environment on exit."""
    previous = dict(os.environ)
    for key in tuple(os.environ):
        if key.lower().endswith('_proxy'):
            os.environ.pop(key)
    for key, subdir in (("HOME", "home"), ("TMPDIR", "tmp"),
                        ("RAPTOR_OUT_DIR", "out"), ("RAPTOR_REGISTRY_HOME", "registry")):
        directory = root / subdir
        directory.mkdir(mode=0o700)
        os.environ[key] = str(directory)
    from core.config import RaptorConfig
    previous_logs = RaptorConfig.LOG_DIR
    RaptorConfig.LOG_DIR = root / "out/logs"
    try:
        yield
    finally:
        RaptorConfig.LOG_DIR = previous_logs
        os.environ.clear()
        os.environ.update(previous)


def check_confined(checkout: Path) -> None:
    checkout = checkout.resolve(strict=True)
    sys.path.insert(0, str(checkout))
    if os.environ.get("RAPTOR_WEB_BROWSER_EXECUTABLE") != "/usr/bin/chromium":
        raise ValueError("confined container check must select Debian Chromium")
    if not Path("/usr/share/doc/chromium/copyright").is_file():
        raise ValueError("Chromium package copyright inventory is missing")
    with tempfile.TemporaryDirectory(prefix="raptor-web-browser-container-") as scratch:
        root = Path(scratch)
        with disposable_environment(root):
            from packages.web.browser import BrowserEngine
            public = root / "public"
            public.mkdir()
            (public / "index.html").write_text(
                '<html><body><script>let a=document.createElement("a");'
                'a.href="/owned-js";a.textContent="owned";'
                'document.body.appendChild(a)</script></body></html>', encoding="utf-8")
            server = ThreadingHTTPServer(("127.0.0.1", 0),
                partial(SimpleHTTPRequestHandler, directory=str(public)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                for waived in (False, True):
                    with BrowserEngine(base, allow_unsandboxed_chromium=waived) as engine:
                        rendered = engine.render(base + "/index.html")
                        if rendered is None or base + "/owned-js" not in rendered.links:
                            raise ValueError("confined Debian Chromium did not execute JavaScript")
                        cdp = engine._browser.new_browser_cdp_session()
                        try:
                            arguments = cdp.send("Browser.getBrowserCommandLine")["arguments"]
                        finally:
                            cdp.detach()
                        if ("--no-sandbox" in arguments) is not waived:
                            raise ValueError("Debian Chromium inner sandbox policy drifted")
                        print("Confined Debian Chromium passed; inner sandbox:", not waived)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confined", type=Path, metavar="CHECKOUT",
                        help="require both browser modes through RAPTOR's sandbox")
    args = parser.parse_args()
    if args.confined:
        check_confined(args.confined)
    else:
        check_basic()


if __name__ == "__main__":
    main()
