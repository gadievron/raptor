"""Tests for the per-tool egress-proxy hostname helpers.

Three-layer resolution: operator override → calibrated profile →
static default. Each helper goes through ``_resolve`` so the layered
behaviour is uniform across tools; tests cover one tool per layer
plus a couple of cross-tool sanity checks (env-key disambiguation,
reset).
"""

from __future__ import annotations

import json
import subprocess
from unittest import mock

import pytest

from packages.sca.resolvers import _proxy_hosts


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test starts with an empty per-process memo so ordering
    doesn't matter."""
    _proxy_hosts._reset_calibrate_cache_for_tests()
    yield
    _proxy_hosts._reset_calibrate_cache_for_tests()


@pytest.fixture
def override_config(tmp_path, monkeypatch):
    """Redirect ``_OVERRIDE_CONFIG_PATH`` to a tmp file. Tests
    populate it via the returned ``write`` callable to exercise the
    override layer."""
    cfg = tmp_path / "sca-proxy-hosts.json"
    monkeypatch.setattr(_proxy_hosts, "_OVERRIDE_CONFIG_PATH", cfg)

    def write(data):
        cfg.write_text(json.dumps(data), encoding="utf-8")
    return write


# ---------------------------------------------------------------------
# Static-default layer
# ---------------------------------------------------------------------


def test_pip_default_when_no_override_no_calibration():
    """Cold path: no override file, no resolvable binary →
    documented PyPI default returned verbatim."""
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]


def test_npm_default_when_no_override_no_calibration():
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_npm()
    assert hosts == ["registry.npmjs.org"]


def test_cargo_default_when_no_override_no_calibration():
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_cargo()
    assert hosts == ["crates.io", "index.crates.io", "static.crates.io"]


def test_gomod_default_when_no_override_no_calibration():
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_gomod()
    assert hosts == ["proxy.golang.org", "sum.golang.org"]


# ---------------------------------------------------------------------
# Override layer
# ---------------------------------------------------------------------


def test_pip_override_takes_precedence(override_config):
    """Override config beats both calibrate and default."""
    override_config({"pip": ["mirror.corp.example.com"]})
    hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["mirror.corp.example.com"]


def test_per_tool_override_independence(override_config):
    """Each tool reads its own key — pip override doesn't leak into
    npm. Operators can override one tool without disturbing the
    others."""
    override_config({"pip": ["pypi.corp.example.com"]})
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        pip_hosts = _proxy_hosts.proxy_hosts_for_pip()
        npm_hosts = _proxy_hosts.proxy_hosts_for_npm()
    assert pip_hosts == ["pypi.corp.example.com"]
    assert npm_hosts == ["registry.npmjs.org"]   # default


def test_override_dedupes_and_strips_garbage(override_config):
    """Override config is hand-edited; tolerate duplicates and
    non-string entries silently."""
    override_config({"npm": [
        "registry.example.com",
        "",                      # empty-string — dropped
        "registry.example.com",  # duplicate — dropped
        123,                     # non-string — dropped
        "mirror.example.com",
    ]})
    hosts = _proxy_hosts.proxy_hosts_for_npm()
    assert hosts == ["registry.example.com", "mirror.example.com"]


def test_override_with_unknown_tool_falls_through(override_config):
    """Override config without our tool's key falls through cleanly
    to the default layer rather than returning empty."""
    override_config({"some-other-tool": ["irrelevant.example.com"]})
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_cargo()
    assert hosts == ["crates.io", "index.crates.io", "static.crates.io"]


def test_override_with_malformed_json_falls_through(override_config,
                                                    tmp_path):
    """A corrupted override config is treated as 'no override' rather
    than crashing the resolver — production failure mode is loud at
    the proxy, not silent at startup."""
    _proxy_hosts._OVERRIDE_CONFIG_PATH.write_text(
        "{not valid json", encoding="utf-8",
    )
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]


def test_override_with_binary_file_falls_through(override_config,
                                                 tmp_path):
    """Operator pointed override path at a non-UTF-8 file by mistake
    (a binary, image, etc.). Must not crash the resolver."""
    # Bytes that are valid in latin-1 but invalid UTF-8 — would crash
    # `read_text(encoding='utf-8')` without our defensive catch.
    _proxy_hosts._OVERRIDE_CONFIG_PATH.write_bytes(
        b"\xff\xfe\x00\x00 not utf-8",
    )
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]


# ---------------------------------------------------------------------
# Calibrated layer
# ---------------------------------------------------------------------


def _profile(proxy_hosts):
    """Build a stub object with a ``proxy_hosts`` attribute that the
    helper reads — matches the SandboxProfile shape without pulling
    in the real dataclass."""
    obj = mock.Mock()
    obj.proxy_hosts = proxy_hosts
    return obj


def test_calibrated_proxy_hosts_used_when_populated():
    """When calibration captured non-empty proxy_hosts (e.g. operator
    ran a network-engaging probe via the libexec CLI), they take
    precedence over the static default."""
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/pip"), \
         mock.patch.object(_proxy_hosts, "_calibrated_profile",
                           return_value=_profile(["pypi.snapshot.example.com"])):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.snapshot.example.com"]


def test_calibrated_empty_proxy_hosts_falls_through_to_default():
    """``--version`` calibration captures filesystem reach but no
    network — proxy_hosts is empty. The helper must fall through to
    default rather than returning an empty allowlist (which would
    deny all traffic)."""
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/pip"), \
         mock.patch.object(_proxy_hosts, "_calibrated_profile",
                           return_value=_profile([])):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]


def test_calibrated_load_failure_falls_through_to_default():
    """Calibration raising (binary missing, ptrace blocked, sandbox
    bug, etc.) must NOT propagate to the resolver — fall through to
    default cleanly."""
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/pip"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=RuntimeError("observe-mode unavailable"),
         ):
        hosts = _proxy_hosts.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]


def test_calibrated_timeout_falls_through_to_default():
    """``subprocess.TimeoutExpired`` from the calibration probe must
    not crash the resolver. Surfaced empirically: a sandboxed ``npm
    --version`` on cold systems can exceed the 20s default."""
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/npm"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=subprocess.TimeoutExpired(
                ["npm", "--version"], 20,
            ),
         ):
        hosts = _proxy_hosts.proxy_hosts_for_npm()
    assert hosts == ["registry.npmjs.org"]


def test_calibrate_per_process_memo_avoids_repeat_loads():
    """Multiple resolver invocations during one scan should hit the
    in-memory memo, not re-stat the on-disk cache file each time."""
    call_count = [0]

    def _counting_load(*args, **kwargs):
        call_count[0] += 1
        return _profile([])

    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/pip"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_counting_load,
         ):
        for _ in range(5):
            _proxy_hosts.proxy_hosts_for_pip()

    assert call_count[0] == 1, (
        f"expected 1 calibrate call across 5 resolver invocations, "
        f"got {call_count[0]} — memoisation broke"
    )


# ---------------------------------------------------------------------
# Per-tool env-key fingerprinting
# ---------------------------------------------------------------------


def test_pip_calibration_includes_index_url_in_cache_key():
    """``PIP_INDEX_URL`` must be part of the calibrate cache key so a
    pip used with two different registries gets two distinct cache
    entries (no profile bleeding across configs)."""
    captured = {}

    def _capture_load(bin_path, **kwargs):
        captured.update(kwargs)
        return _profile([])

    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/pip"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_capture_load,
         ):
        _proxy_hosts.proxy_hosts_for_pip()

    assert "env_keys" in captured
    env_keys = tuple(captured["env_keys"])
    assert "PIP_INDEX_URL" in env_keys
    assert "PIP_EXTRA_INDEX_URL" in env_keys


def test_gomod_calibration_includes_goproxy_in_cache_key():
    """Same property for go: ``GOPROXY`` / ``GOSUMDB`` / ``GOPRIVATE``
    discriminate the cache so the same `go` binary used in two
    GOPROXY configs has two profiles."""
    captured = {}

    def _capture_load(bin_path, **kwargs):
        captured.update(kwargs)
        return _profile([])

    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/usr/bin/go"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_capture_load,
         ):
        _proxy_hosts.proxy_hosts_for_gomod()

    env_keys = tuple(captured["env_keys"])
    assert "GOPROXY" in env_keys
    assert "GOSUMDB" in env_keys
    assert "GOPRIVATE" in env_keys


# ---------------------------------------------------------------------
# Resolver-class wiring
# ---------------------------------------------------------------------


def test_pip_resolver_property_calls_helper():
    """``PipResolver().proxy_hosts`` resolves through the helper —
    the wiring is alive, not just present."""
    from packages.sca.resolvers.pip import PipResolver
    with mock.patch(
        "packages.sca.resolvers._proxy_hosts.proxy_hosts_for_pip",
        return_value=["sentinel.example.com"],
    ):
        assert PipResolver().proxy_hosts == ["sentinel.example.com"]


def test_npm_resolver_property_calls_helper():
    from packages.sca.resolvers.npm import NpmResolver
    with mock.patch(
        "packages.sca.resolvers._proxy_hosts.proxy_hosts_for_npm",
        return_value=["sentinel.example.com"],
    ):
        assert NpmResolver().proxy_hosts == ["sentinel.example.com"]


def test_cargo_resolver_property_calls_helper():
    from packages.sca.resolvers.cargo import CargoResolver
    with mock.patch(
        "packages.sca.resolvers._proxy_hosts.proxy_hosts_for_cargo",
        return_value=["sentinel.example.com"],
    ):
        assert CargoResolver().proxy_hosts == ["sentinel.example.com"]


def test_gomod_resolver_property_calls_helper():
    from packages.sca.resolvers.gomod import GoResolver
    with mock.patch(
        "packages.sca.resolvers._proxy_hosts.proxy_hosts_for_gomod",
        return_value=["sentinel.example.com"],
    ):
        assert GoResolver().proxy_hosts == ["sentinel.example.com"]


# ---------------------------------------------------------------------
# End-to-end (real calibrate, real binary)
# ---------------------------------------------------------------------


@pytest.mark.skipif(
    not __import__("shutil").which("python3"),
    reason="python3 not on PATH — E2E needs a real --version-supporting binary",
)
def test_e2e_real_calibration_against_python3_binary(tmp_path,
                                                    monkeypatch):
    """End-to-end: a real binary (`python3`) goes through the
    full chain — `_resolve_bin` → `load_or_calibrate` → seatbelt /
    ptrace observe-mode → cache write → memo. Verifies the wiring
    holds against the live calibrate substrate, not just mocks.

    `python3` stands in for pip/npm/cargo/go: every Linux/macOS host
    has it, it supports `--version`, and `--version` doesn't network
    (so proxy_hosts captures empty → fall through to default —
    which is what we assert).

    Cache lands in an isolated tmp HOME so a successful calibrate
    doesn't pollute the operator's real cache.
    """
    import shutil as _shutil
    from packages.sca.resolvers import _proxy_hosts as ph

    # Redirect HOME so the calibrate cache is isolated to tmp_path.
    monkeypatch.setenv("HOME", str(tmp_path))
    # _proxy_hosts caches the override path at module load — ours
    # didn't exist when the module loaded, so override layer is
    # already a no-op for this test, but reset for safety.
    monkeypatch.setattr(ph, "_OVERRIDE_CONFIG_PATH",
                        tmp_path / ".config" / "raptor" /
                        "sca-proxy-hosts.json")

    # Force the helper to think python3 is the pip binary so we run
    # against a known-installed program.
    real_python = _shutil.which("python3")
    assert real_python is not None
    monkeypatch.setattr(ph, "_resolve_bin",
                        lambda name: real_python)

    # Pre-clear the per-process memo.
    ph._reset_calibrate_cache_for_tests()

    # Calibration should run, capture filesystem reach (paths_read
    # non-empty), produce empty proxy_hosts (--version doesn't
    # network), and the helper falls through to PyPI default.
    hosts = ph.proxy_hosts_for_pip()
    assert hosts == ["pypi.org", "files.pythonhosted.org"]

    # Memoised — second call returns same and doesn't re-spawn.
    assert real_python in ph._CALIBRATED_CACHE
    cached = ph._CALIBRATED_CACHE[real_python]
    if cached is not None:
        # Non-None cache means the probe succeeded. Sanity-check
        # the captured profile's shape: it has either some paths_read
        # (real probe captured kernel events) OR is empty (e.g.
        # observe-mode degraded silently — best-effort, fine).
        assert hasattr(cached, "proxy_hosts")
        assert hasattr(cached, "paths_read")
        # python3 --version doesn't network, so calibrated proxy_hosts
        # MUST be empty — this is the load-bearing invariant the
        # resolver's three-layer fallthrough depends on.
        assert list(cached.proxy_hosts) == []


# ---------------------------------------------------------------------
# Secondary resolvers (bundler / composer / gradle / maven / nuget /
# pnpm / poetry / yarn) — same shape, different registries.
# ---------------------------------------------------------------------


# (helper, expected default, override key, bin name) for the 8 secondary
# resolvers. Pinned so a future host-list change has to update the test
# explicitly — guards against silent allowlist drift.
_SECONDARY = [
    ("proxy_hosts_for_bundler",
     ["rubygems.org", "index.rubygems.org"],
     "bundler", "bundle"),
    ("proxy_hosts_for_composer",
     ["repo.packagist.org", "packagist.org"],
     "composer", "composer"),
    ("proxy_hosts_for_gradle",
     ["repo.maven.apache.org", "repo1.maven.org",
      "plugins.gradle.org", "services.gradle.org"],
     "gradle", "gradle"),
    ("proxy_hosts_for_maven",
     ["repo.maven.apache.org", "repo1.maven.org"],
     "maven", "mvn"),
    ("proxy_hosts_for_nuget",
     ["api.nuget.org", "nuget.org"],
     "nuget", "dotnet"),
    ("proxy_hosts_for_pnpm",
     ["registry.npmjs.org"],
     "pnpm", "pnpm"),
    ("proxy_hosts_for_poetry",
     ["pypi.org", "files.pythonhosted.org"],
     "poetry", "poetry"),
    ("proxy_hosts_for_yarn",
     ["registry.yarnpkg.com", "registry.npmjs.org"],
     "yarn", "yarn"),
]


@pytest.mark.parametrize(
    "fn_name,expected_default,override_key,_bin", _SECONDARY,
)
def test_secondary_default_when_no_override_no_calibration(
    fn_name, expected_default, override_key, _bin,
):
    """Each secondary helper returns its documented static default
    when (a) no override config exists and (b) no binary is on PATH."""
    fn = getattr(_proxy_hosts, fn_name)
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value=None):
        assert fn() == expected_default


@pytest.mark.parametrize(
    "fn_name,_expected_default,override_key,_bin", _SECONDARY,
)
def test_secondary_override_takes_precedence(
    override_config, fn_name, _expected_default, override_key, _bin,
):
    """Override config under the per-tool key beats default."""
    override_config({override_key: ["mirror.corp.example.com"]})
    fn = getattr(_proxy_hosts, fn_name)
    assert fn() == ["mirror.corp.example.com"]


@pytest.mark.parametrize(
    "fn_name,_expected_default,_override_key,_bin", _SECONDARY,
)
def test_secondary_calibrated_proxy_hosts_used_when_populated(
    fn_name, _expected_default, _override_key, _bin,
):
    """Calibrated profile with non-empty proxy_hosts (operator ran a
    network-engaging probe) wins over the static default. Mirrors
    the cc_dispatch / pip behaviour."""
    fake = mock.Mock()
    fake.proxy_hosts = ["snapshot.example.com"]
    fn = getattr(_proxy_hosts, fn_name)
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/fake/bin"), \
         mock.patch.object(_proxy_hosts, "_calibrated_profile",
                           return_value=fake):
        assert fn() == ["snapshot.example.com"]


# Per-tool env_keys disambiguate the calibrate cache; pinning them
# guards against accidental key drift that would silently merge two
# distinct configurations into one cache entry.
_SECONDARY_ENV_KEYS = [
    ("proxy_hosts_for_bundler", "BUNDLE_GEMFILE"),
    ("proxy_hosts_for_composer", "COMPOSER_HOME"),
    ("proxy_hosts_for_gradle", "GRADLE_USER_HOME"),
    ("proxy_hosts_for_maven", "MAVEN_OPTS"),
    ("proxy_hosts_for_nuget", "NUGET_PACKAGES"),
    ("proxy_hosts_for_pnpm", "NPM_CONFIG_REGISTRY"),
    ("proxy_hosts_for_poetry", "POETRY_REPOSITORIES_PRIMARY_URL"),
    ("proxy_hosts_for_yarn", "YARN_REGISTRY"),
]


@pytest.mark.parametrize("fn_name,expected_key", _SECONDARY_ENV_KEYS)
def test_secondary_calibration_includes_documented_env_key(
    fn_name, expected_key,
):
    """Each secondary helper's calibrate cache key includes the
    documented env-var discriminator. Pinned so a future env_keys
    edit doesn't silently broaden the cache scope."""
    captured = {}

    def _capture_load(bin_path, **kwargs):
        captured.update(kwargs)
        fake = mock.Mock()
        fake.proxy_hosts = []
        return fake

    fn = getattr(_proxy_hosts, fn_name)
    with mock.patch.object(_proxy_hosts, "_resolve_bin",
                           return_value="/fake/bin"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_capture_load,
         ):
        fn()

    assert "env_keys" in captured
    assert expected_key in tuple(captured["env_keys"])


# Resolver-class wiring — ensure each secondary resolver's @property
# routes through the helper.
_RESOLVER_WIRING = [
    ("packages.sca.resolvers.bundler", "BundlerResolver",
     "proxy_hosts_for_bundler"),
    ("packages.sca.resolvers.composer", "ComposerResolver",
     "proxy_hosts_for_composer"),
    ("packages.sca.resolvers.gradle", "GradleResolver",
     "proxy_hosts_for_gradle"),
    ("packages.sca.resolvers.maven", "MavenResolver",
     "proxy_hosts_for_maven"),
    ("packages.sca.resolvers.nuget", "NugetResolver",
     "proxy_hosts_for_nuget"),
    ("packages.sca.resolvers.pnpm", "PnpmResolver",
     "proxy_hosts_for_pnpm"),
    ("packages.sca.resolvers.poetry", "PoetryResolver",
     "proxy_hosts_for_poetry"),
    ("packages.sca.resolvers.yarn", "YarnResolver",
     "proxy_hosts_for_yarn"),
]


@pytest.mark.parametrize("module_path,cls_name,helper_name",
                         _RESOLVER_WIRING)
def test_secondary_resolver_property_calls_helper(
    module_path, cls_name, helper_name,
):
    """Each secondary resolver's ``proxy_hosts`` property routes
    through the per-tool helper. Patches the helper to a sentinel
    return; if the wiring's wrong, the assertion catches it."""
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, cls_name)
    sentinel = ["sentinel.example.com"]
    with mock.patch(
        f"packages.sca.resolvers._proxy_hosts.{helper_name}",
        return_value=sentinel,
    ):
        assert cls().proxy_hosts == sentinel
