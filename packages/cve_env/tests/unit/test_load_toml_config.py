"""Phase 43.1.1 (2026-05-16): coverage gap closure for `_load_toml_config`.

Per Phase 42.5 coverage report — `_load_toml_config` was in the MED-risk
no-test category. The function reads `cve-env.toml` from CWD or
`CVE_ENV_CONFIG_FILE` env var; errors are intentionally non-fatal.

Tests cover:
- Missing file → empty dict
- Empty file → empty dict
- Malformed TOML → empty dict (non-fatal error swallowed)
- Valid TOML → parsed dict
- CVE_ENV_CONFIG_FILE override

Location: src/cve_env/config.py:33-48.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import cve_env.config as cve_config


def _reload_module_with_env(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], cwd: Path
) -> None:
    """Reload cve_env.config under a controlled env + cwd so _load_toml_config
    re-runs at module import. Used to test that the module-level _TOML_CONFIG
    initialization picks up the env var. NOT used for the function tests below
    (which can call _load_toml_config directly).
    """
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(cwd)
    importlib.reload(cve_config)


def test_load_toml_returns_empty_when_file_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No cve-env.toml in CWD → empty dict."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CVE_ENV_CONFIG_FILE", raising=False)
    result = cve_config._load_toml_config()
    assert result == {}


def test_load_toml_returns_empty_when_env_var_points_to_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CVE_ENV_CONFIG_FILE points to non-existent file → empty dict."""
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(tmp_path / "nonexistent.toml"))
    result = cve_config._load_toml_config()
    assert result == {}


def test_load_toml_returns_empty_on_empty_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Empty TOML file → empty dict (valid TOML, no keys)."""
    cfg = tmp_path / "empty.toml"
    cfg.write_text("")
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(cfg))
    result = cve_config._load_toml_config()
    assert result == {}


def test_load_toml_swallows_malformed_toml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Malformed TOML → empty dict (errors are intentionally non-fatal).

    Docstring: "Errors are intentionally non-fatal (env vars + code defaults
    still work)."
    """
    cfg = tmp_path / "bad.toml"
    cfg.write_text("this is = NOT valid TOML [[[")
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(cfg))
    result = cve_config._load_toml_config()
    assert result == {}


def test_load_toml_parses_valid_top_level_table(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Valid TOML with [budget] table → dict with budget key."""
    cfg = tmp_path / "cve-env.toml"
    cfg.write_text("[budget]\nresearch = 0.50\nverify = 0.30\n")
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(cfg))
    result = cve_config._load_toml_config()
    assert result == {"budget": {"research": 0.50, "verify": 0.30}}


def test_load_toml_parses_nested_tables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nested tables work — needed for _get_toml_value's dotted-path access."""
    cfg = tmp_path / "cve-env.toml"
    cfg.write_text('[budget.modes]\nresearch = "hard"\nverify = "soft"\n')
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(cfg))
    result = cve_config._load_toml_config()
    assert result == {"budget": {"modes": {"research": "hard", "verify": "soft"}}}


def test_load_toml_reads_from_cwd_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No CVE_ENV_CONFIG_FILE → reads `cve-env.toml` from CWD."""
    cfg = tmp_path / "cve-env.toml"
    cfg.write_text('[test]\nkey = "value"\n')
    monkeypatch.delenv("CVE_ENV_CONFIG_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    result = cve_config._load_toml_config()
    assert result == {"test": {"key": "value"}}


def test_load_toml_handles_unreadable_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If file is a directory (not regular file), is_file() returns False
    → empty dict, no exception."""
    not_a_file = tmp_path / "cve-env.toml"
    not_a_file.mkdir()  # directory, not file
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(not_a_file))
    result = cve_config._load_toml_config()
    assert result == {}
