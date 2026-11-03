"""The availability probe and browser engine select the same explicit runtime."""
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from packages.web.browser import BrowserEngine, browser_available


@pytest.fixture
def driver(monkeypatch):
    package = ModuleType("playwright")
    package.__path__ = []
    api = ModuleType("playwright.sync_api")
    controller = MagicMock()
    runtime = MagicMock()
    controller.__enter__.return_value = runtime
    controller.start.return_value = runtime
    api.sync_playwright = MagicMock(return_value=controller)
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", api)
    monkeypatch.setattr(BrowserEngine, "_proxy_settings", lambda self: None)
    monkeypatch.delenv("RAPTOR_WEB_BROWSER_EXECUTABLE", raising=False)
    return runtime, controller


@pytest.mark.parametrize("path", [None, "/usr/bin/chromium", "/opt/browser install/chromium"])
def test_probe_and_engine_share_browser_selection(driver, monkeypatch, path):
    runtime, _ = driver
    if path is not None:
        monkeypatch.setenv("RAPTOR_WEB_BROWSER_EXECUTABLE", path)
    assert browser_available()
    with BrowserEngine("https://target.invalid"):
        pass
    assert runtime.chromium.launch.call_count == 2
    for call in runtime.chromium.launch.call_args_list:
        expected = {"headless": True}
        if path is not None:
            expected["executable_path"] = path
        assert call.kwargs == expected
    context_args = runtime.chromium.launch.return_value.new_context.call_args.kwargs
    assert context_args["service_workers"] == "block"


def test_failed_explicit_browser_never_falls_back(driver, monkeypatch):
    runtime, _ = driver
    monkeypatch.setenv("RAPTOR_WEB_BROWSER_EXECUTABLE", "/missing/chromium")
    runtime.chromium.launch.side_effect = RuntimeError("missing browser")
    assert not browser_available()
    runtime.chromium.launch.assert_called_once_with(headless=True, executable_path="/missing/chromium")


def test_relative_override_fails_before_starting_driver(driver, monkeypatch):
    runtime, controller = driver
    monkeypatch.setenv("RAPTOR_WEB_BROWSER_EXECUTABLE", "./chromium")
    with pytest.raises(ValueError, match="absolute path"):
        with BrowserEngine("https://target.invalid"):
            pass
    controller.start.assert_not_called()
    runtime.chromium.launch.assert_not_called()
