"""Cross-site closure for the egress proxy-hosts resolution ladder.

Four binary-scoped allowlists (cc_dispatch, CodeQL pack download,
SCA resolvers, semgrep) resolve operator override → calibrated
profile → static default. Nothing used to pin that the four ladders
agreed on order and fallthrough semantics — they drifted on cache
keying and on what an empty override means. These tests parametrise
the SAME assertions over every site, and a registry check keeps new
``proxy_hosts_for_*`` providers from re-rolling the layers.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from core.sandbox import calibrated_hosts  # noqa: E402


class _Site:
    def __init__(self, module_name: str, fn_name: str, override_key: str,
                 default_marker: str, bin_attr: str):
        self.module = importlib.import_module(module_name)
        self.name = module_name
        self.fn = getattr(self.module, fn_name)
        self.override_key = override_key
        self.default_marker = default_marker
        self.bin_attr = bin_attr


def _sites() -> list[_Site]:
    return [
        _Site("core.llm.cc_proxy_hosts", "proxy_hosts_for_cc_dispatch",
              "proxy_hosts", "api.anthropic.com", "_resolve_claude_bin"),
        _Site("packages.codeql.codeql_proxy_hosts", "proxy_hosts_for_codeql",
              "proxy_hosts", "ghcr.io", "_resolve_codeql_bin"),
        _Site("packages.sca.resolvers._proxy_hosts", "proxy_hosts_for_pip",
              "pip", "pypi.org", "_resolve_bin"),
        _Site("packages.semgrep._proxy_hosts", "proxy_hosts_for_semgrep",
              "hosts", "semgrep.dev", "_resolve_semgrep_bin"),
    ]


_SITE_IDS = [s.name for s in _sites()]


class _FakeProfile:
    def __init__(self, proxy_hosts):
        self.proxy_hosts = list(proxy_hosts)
        self.paths_read = []
        self.paths_stat = []


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    # Neutralise cc's provider env-var layer (it sits between the
    # calibrated layer and the Anthropic default; a host running
    # under Bedrock/Vertex would otherwise shift the default
    # assertions).
    from core.llm import cc_proxy_hosts as _cc
    for key in _cc._PROVIDER_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    # Point every site's override path into an empty tmp dir and
    # reset the shared calibrate memo around each test.
    for site in _sites():
        monkeypatch.setattr(
            site.module, "_OVERRIDE_CONFIG_PATH",
            tmp_path / f"{site.override_key}-{site.module.__name__.split('.')[-1]}.json",
        )
    calibrated_hosts.reset_cache_for_tests()
    yield
    calibrated_hosts.reset_cache_for_tests()


def _configure_calibration(monkeypatch, site, profile):
    """Make calibration succeed with ``profile`` for the site."""
    # A resolvable binary path (contents never executed — the
    # shared profile loader below is patched out).
    monkeypatch.setattr(site.module, site.bin_attr,
                        lambda *a, **k: "/opt/bin/fake-tool")
    monkeypatch.setattr(calibrated_hosts, "calibrated_profile",
                        lambda *a, **k: profile)


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_default_when_nothing_configured(site, monkeypatch):
    _configure_calibration(monkeypatch, site, None)
    hosts = site.fn()
    assert site.default_marker in hosts


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_calibrated_hosts_beat_default(site, monkeypatch):
    _configure_calibration(
        monkeypatch, site, _FakeProfile(["calibrated.example"]))
    assert site.fn() == ["calibrated.example"]


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_empty_calibrated_falls_through_to_default(site, monkeypatch):
    # The canonical --version probe doesn't network: a profile with
    # empty proxy_hosts means "nothing calibrated", never "deny".
    _configure_calibration(monkeypatch, site, _FakeProfile([]))
    hosts = site.fn()
    assert site.default_marker in hosts


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_override_beats_calibrated_and_default(site, monkeypatch):
    _configure_calibration(
        monkeypatch, site, _FakeProfile(["calibrated.example"]))
    site.module._OVERRIDE_CONFIG_PATH.write_text(
        json.dumps({site.override_key: ["override.corp.example"]}))
    assert site.fn() == ["override.corp.example"]


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_empty_override_is_deny_all_not_default(site, monkeypatch):
    # {"<key>": []} is an explicit operator deny-all. It must never
    # fall through to the permissive default. Encoding: loopback-only
    # (the sandbox rejects an empty allowlist; the CONNECT proxy
    # refuses loopback targets — so every remote host stays denied).
    _configure_calibration(monkeypatch, site, None)
    site.module._OVERRIDE_CONFIG_PATH.write_text(
        json.dumps({site.override_key: []}))
    hosts = site.fn()
    assert site.default_marker not in hosts
    assert hosts in ([], ["127.0.0.1", "localhost"])


@pytest.mark.parametrize("site", _sites(), ids=_SITE_IDS)
def test_malformed_override_falls_through(site, monkeypatch):
    _configure_calibration(monkeypatch, site, None)
    site.module._OVERRIDE_CONFIG_PATH.write_bytes(b"\xff\xfenot json")
    hosts = site.fn()
    assert site.default_marker in hosts


# ---------------------------------------------------------------------------
# Registry closure — new providers must use the shared layers
# ---------------------------------------------------------------------------

#: Documented-deliberate exceptions, with the reason the shared
#: loaders cannot serve them. Additions require editing this test.
_EXCLUDED = {
    # Must stay stdlib-only (runs before core.config is importable in
    # the sandboxed BigQuery child); carries its own mirrored loader
    # with the same empty-is-deny-all contract.
    "core/forensics/bq_query.py",
}


def _provider_files() -> list[Path]:
    hits = []
    for root in ("core", "packages", "plugins"):
        for p in (REPO_ROOT / root).rglob("*.py"):
            parts = set(p.parts)
            if "tests" in parts or "scripts" in parts:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "def proxy_hosts_for_" in text:
                hits.append(p)
    return hits


def test_registry_sees_the_known_providers():
    rels = {str(p.relative_to(REPO_ROOT)) for p in _provider_files()}
    for site in ("core/llm/cc_proxy_hosts.py",
                 "packages/codeql/codeql_proxy_hosts.py",
                 "packages/sca/resolvers/_proxy_hosts.py",
                 "packages/semgrep/_proxy_hosts.py",
                 "core/git/_proxy_hosts.py"):
        assert site in rels, f"scan lost a known provider: {site}"


def test_every_provider_uses_the_shared_layers():
    offenders = []
    for p in _provider_files():
        rel = str(p.relative_to(REPO_ROOT))
        if rel in _EXCLUDED:
            continue
        text = p.read_text(encoding="utf-8")
        if "load_hosts_override" not in text:
            offenders.append(f"{rel}: override layer not routed through "
                             "core.config.hosts_override")
        if "load_or_calibrate" in text or "_calibrated_profile" in text:
            if "calibrated_hosts" not in text:
                offenders.append(f"{rel}: calibrated layer not routed "
                                 "through core.sandbox.calibrated_hosts")
    assert offenders == [], "\n".join(offenders)
