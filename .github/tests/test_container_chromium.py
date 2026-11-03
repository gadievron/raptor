"""Published browser choice and compatibility check stay coupled."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_container_uses_distro_browser_and_checks_before_publication():
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    assert "apt-get install -y --no-install-recommends chromium" in dockerfile
    assert "playwright install" not in dockerfile
    assert "/root/.cache/ms-playwright" in dockerfile
    assert "ENV RAPTOR_WEB_BROWSER_EXECUTABLE=/usr/bin/chromium" in dockerfile
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    assert workflow.index("check-browser.py") < workflow.index("- name: Publish verified image")


def test_confined_browser_acceptance_is_required_before_publication():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    assert workflow.index("enable-userns") < workflow.index("--confined /workspaces/raptor")
    assert workflow.index("--confined /workspaces/raptor") < workflow.index("- name: Publish verified image")
    assert '--mount type=bind,source="$GITHUB_WORKSPACE",target=/workspaces/raptor,readonly' in workflow
    assert 'docker run --rm --network none' in workflow
    assert '--security-opt apparmor=unconfined' in workflow
    assert '--security-opt systempaths=unconfined' in workflow
    assert "--security-opt seccomp=unconfined" in workflow


def test_confined_check_exercises_both_policies_with_disposable_state(tmp_path, monkeypatch):
    import importlib.util
    import os
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from packages.web import browser
    spec = importlib.util.spec_from_file_location("container_browser_check", ROOT / ".devcontainer/check-browser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("RAPTOR_WEB_BROWSER_EXECUTABLE", "/usr/bin/chromium")
    monkeypatch.setenv("HOME", str(tmp_path / "operator-home"))
    monkeypatch.setenv("HTTP_PROXY", "http://operator.invalid")
    previous = dict(os.environ)
    original_is_file = module.Path.is_file
    monkeypatch.setattr(module.Path, "is_file", lambda p: True if str(p) == "/usr/share/doc/chromium/copyright" else original_is_file(p))
    selected = []
    def engine(base, *, allow_unsandboxed_chromium):
        assert os.environ["HOME"] != previous["HOME"]
        assert "HTTP_PROXY" not in os.environ
        selected.append(allow_unsandboxed_chromium)
        instance = MagicMock()
        instance.__enter__.return_value = instance
        instance.render.return_value = SimpleNamespace(links=[base + "/owned-js"])
        instance._browser.new_browser_cdp_session.return_value.send.return_value = {
            "arguments": ["--no-sandbox"] if allow_unsandboxed_chromium else ["--enable-automation"]}
        return instance
    monkeypatch.setattr(browser, "BrowserEngine", engine)
    monkeypatch.setattr(module.sys, "path", list(module.sys.path))
    module.check_confined(ROOT)
    assert selected == [False, True]
    assert dict(os.environ) == previous
