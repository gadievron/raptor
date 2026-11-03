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
