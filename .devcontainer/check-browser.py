#!/usr/bin/env python3
"""Check the published container's system browser with an offline page."""
import os
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> None:
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


if __name__ == "__main__":
    main()
