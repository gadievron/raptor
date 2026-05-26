"""Tests for ``packages.sca.private_registry`` and the registry-
client integration paths."""

from __future__ import annotations

from packages.sca.private_registry import (
    RegistryOverride,
    get,
    hosts_for_overrides,
    load_overrides,
)


# ---------------------------------------------------------------------------
# load_overrides — env-var detection
# ---------------------------------------------------------------------------


def test_no_env_returns_empty():
    assert load_overrides({}) == {}


def test_pip_index_url_picked_up():
    overrides = load_overrides({
        "PIP_INDEX_URL": "https://artifactory.example.com/pypi/simple/",
    })
    assert "PyPI" in overrides
    assert overrides["PyPI"].base_url == \
        "https://artifactory.example.com/pypi/simple/"
    assert overrides["PyPI"].auth_header is None


def test_npm_config_registry_picked_up():
    overrides = load_overrides({
        "NPM_CONFIG_REGISTRY": "https://nexus.example.com/npm/",
    })
    assert overrides["npm"].base_url == "https://nexus.example.com/npm/"


def test_maven_via_raptor_var():
    overrides = load_overrides({
        "RAPTOR_SCA_MAVEN_REGISTRY": "https://nexus.example.com/maven2/",
    })
    assert overrides["Maven"].base_url == \
        "https://nexus.example.com/maven2/"


def test_auth_header_companion_var():
    overrides = load_overrides({
        "PIP_INDEX_URL": "https://artifactory.example.com/pypi/simple/",
        "RAPTOR_SCA_PYPI_AUTH": "Bearer xyz123",
    })
    assert overrides["PyPI"].auth_header == "Bearer xyz123"


def test_auth_without_url_ignored():
    """Setting only ``_AUTH`` without ``_URL`` shouldn't create a
    half-formed override."""
    overrides = load_overrides({
        "RAPTOR_SCA_PYPI_AUTH": "Bearer xyz",
    })
    assert "PyPI" not in overrides


def test_non_http_url_rejected():
    """Refuse ``file://`` / ``ftp://`` schemes — same posture as
    core.http.urllib_backend's URL validation."""
    overrides = load_overrides({
        "PIP_INDEX_URL": "file:///etc/passwd",
    })
    assert "PyPI" not in overrides


def test_empty_url_string_treated_as_unset():
    assert load_overrides({"PIP_INDEX_URL": ""}) == {}
    assert load_overrides({"PIP_INDEX_URL": "   "}) == {}


def test_multiple_ecosystems_concurrent():
    overrides = load_overrides({
        "PIP_INDEX_URL": "https://art.example/pypi/",
        "NPM_CONFIG_REGISTRY": "https://art.example/npm/",
        "RAPTOR_SCA_MAVEN_REGISTRY": "https://art.example/maven/",
    })
    assert set(overrides.keys()) == {"PyPI", "npm", "Maven"}


# ---------------------------------------------------------------------------
# hosts_for_overrides — allowlist composition
# ---------------------------------------------------------------------------


def test_extracts_hostnames():
    overrides = {
        "PyPI": RegistryOverride(base_url="https://art.example.com/pypi/"),
        "npm": RegistryOverride(base_url="https://nexus.example.com/npm/"),
    }
    hosts = hosts_for_overrides(overrides)
    assert set(hosts) == {"art.example.com", "nexus.example.com"}


def test_dedups_when_one_host_serves_multiple_ecosystems():
    """An Artifactory deployment commonly hosts pypi + npm + maven
    on the same hostname under different paths. The allowlist
    should list the host once."""
    overrides = {
        "PyPI": RegistryOverride(base_url="https://art.example/pypi/"),
        "npm": RegistryOverride(base_url="https://art.example/npm/"),
        "Maven": RegistryOverride(base_url="https://art.example/maven/"),
    }
    assert hosts_for_overrides(overrides) == ["art.example"]


def test_empty_overrides_returns_empty():
    assert hosts_for_overrides({}) == []


# ---------------------------------------------------------------------------
# get — convenience helper
# ---------------------------------------------------------------------------


def test_get_returns_none_for_missing_ecosystem():
    overrides = load_overrides({"PIP_INDEX_URL": "https://x/"})
    assert get("npm", overrides) is None


def test_get_returns_override_when_present():
    overrides = load_overrides({"PIP_INDEX_URL": "https://x/"})
    assert get("PyPI", overrides).base_url == "https://x/"


# ---------------------------------------------------------------------------
# Integration: PyPIClient picks up overrides at construction time
# ---------------------------------------------------------------------------


def test_pypi_client_uses_override_url(monkeypatch):
    """Setting PIP_INDEX_URL in env causes PyPIClient to fetch from
    the mirror, not pypi.org."""
    monkeypatch.setenv(
        "PIP_INDEX_URL", "https://artifactory.example.com/pypi/simple/",
    )
    monkeypatch.setenv("RAPTOR_SCA_PYPI_AUTH", "Bearer t1")

    from packages.sca.registries.pypi import PyPIClient

    captured = {}

    class _StubHttp:
        def get_json(self, url, headers=None, **kw):
            captured["url"] = url
            captured["headers"] = headers
            return {"info": {}, "releases": {}}

    client = PyPIClient(http=_StubHttp())
    client.get_metadata("requests")
    # PIP_INDEX_URL conventionally points at the simple-index path
    # (``<base>/simple/``); the JSON API lives at
    # ``<base>/pypi/<name>/json``. We strip /simple/ from the
    # configured URL and append /pypi/<name>/json so that mirrors
    # following the standard layout (Artifactory's pypi-virtual,
    # devpi) resolve correctly.
    assert captured["url"] == (
        "https://artifactory.example.com/pypi/pypi/requests/json"
    )
    # Auth header threaded.
    assert captured["headers"] == {"Authorization": "Bearer t1"}


def test_pypi_client_default_when_no_override(monkeypatch):
    """Without PIP_INDEX_URL, PyPIClient hits pypi.org as before
    and omits the Authorization header."""
    monkeypatch.delenv("PIP_INDEX_URL", raising=False)
    monkeypatch.delenv("RAPTOR_SCA_PYPI_AUTH", raising=False)

    from packages.sca.registries.pypi import PyPIClient

    captured = {}

    class _StubHttp:
        def get_json(self, url, headers=None, **kw):
            captured["url"] = url
            captured["headers"] = headers
            return {"info": {}, "releases": {}}

    client = PyPIClient(http=_StubHttp())
    client.get_metadata("requests")
    assert captured["url"] == "https://pypi.org/pypi/requests/json"
    assert captured["headers"] is None


def test_npm_client_uses_override_url(monkeypatch):
    monkeypatch.setenv(
        "NPM_CONFIG_REGISTRY", "https://nexus.example.com/npm/",
    )
    monkeypatch.setenv("RAPTOR_SCA_NPM_AUTH", "Bearer t2")

    from packages.sca.registries.npm import NpmClient

    captured = {}

    class _StubHttp:
        def get_json(self, url, headers=None, **kw):
            captured["url"] = url
            captured["headers"] = headers
            return {}

    NpmClient(http=_StubHttp()).get_metadata("lodash")
    assert captured["url"].startswith("https://nexus.example.com/npm/")
    assert captured["headers"] == {"Authorization": "Bearer t2"}


def test_maven_client_uses_override_url(monkeypatch):
    monkeypatch.setenv(
        "RAPTOR_SCA_MAVEN_REGISTRY",
        "https://nexus.example.com/maven2/",
    )
    monkeypatch.delenv("RAPTOR_SCA_MAVEN_AUTH", raising=False)

    from packages.sca.registries.maven import MavenClient

    captured = {}

    class _StubHttp:
        def get_json(self, url, headers=None, **kw):
            captured["url"] = url
            return {}

    MavenClient(http=_StubHttp()).list_versions(
        "org.springframework:spring-core",
    )
    assert captured["url"].startswith(
        "https://nexus.example.com/maven2/solrsearch/select",
    )


# ---------------------------------------------------------------------------
# Integration: compose_proxy_hosts auto-includes override hosts
# ---------------------------------------------------------------------------


def test_compose_proxy_hosts_includes_overrides(monkeypatch):
    monkeypatch.setenv(
        "PIP_INDEX_URL", "https://artifactory.example.com/pypi/simple/",
    )
    from packages.sca import compose_proxy_hosts

    hosts = compose_proxy_hosts()
    assert "artifactory.example.com" in hosts
    # Static set still present.
    assert "api.osv.dev" in hosts
