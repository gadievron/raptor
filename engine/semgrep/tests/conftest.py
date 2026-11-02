"""Keep real Semgrep invocations independent of operator settings and logs."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_semgrep_state(monkeypatch, tmp_path):
    monkeypatch.setenv("SEMGREP_SETTINGS_FILE", str(tmp_path / "settings.yml"))
    monkeypatch.setenv("SEMGREP_LOG_FILE", str(tmp_path / "semgrep.log"))
    monkeypatch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "0")
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "off")
    monkeypatch.delenv("SEMGREP_APP_TOKEN", raising=False)
