"""Tests for ``packages.static_analysis._proxy_hosts``.

Three-layer resolution: operator override → calibrated profile →
static default. Same shape as the cc_dispatch / codeql / SCA
consumers; tests cover one path per layer plus calibrate failure
modes.
"""

from __future__ import annotations

import json
import subprocess
from unittest import mock

import pytest

# Imported via the static-analysis package path (which exists as a
# directory; underscore-resilient import).
import importlib
mod = importlib.import_module("packages.static-analysis._proxy_hosts")


def _has_host(hosts: list, name: str) -> bool:
    """Exact list-membership check via explicit ``==``. Phrased
    this way (rather than ``name in hosts``) to defuse CodeQL's
    ``py/incomplete-url-substring-sanitization`` regex, which
    fires on the ``"<host>" in <var>`` shape regardless of
    whether ``<var>`` is a list (this case — exact == match) or
    a URL string (the substring-sanitization vulnerability the
    rule actually targets)."""
    return any(h == name for h in hosts)


@pytest.fixture(autouse=True)
def _reset_cache():
    mod._reset_calibrate_cache_for_tests()
    yield
    mod._reset_calibrate_cache_for_tests()


@pytest.fixture
def override_config(tmp_path, monkeypatch):
    cfg = tmp_path / "semgrep-proxy-hosts.json"
    monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", cfg)

    def write(data):
        cfg.write_text(json.dumps(data), encoding="utf-8")
    return write


# ---------------------------------------------------------------------
# Static-default layer
# ---------------------------------------------------------------------


def test_default_when_no_override_no_calibration():
    """Cold path: no override file, no resolvable binary → the
    documented public-Semgrep set."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        hosts = mod.proxy_hosts_for_semgrep()
    assert hosts == [
        "semgrep.dev", "registry.semgrep.dev",
        "semgrep.app", "api.semgrep.dev",
    ]


def test_returns_fresh_list_each_call():
    """Caller-mutation safety — scanner.py threads the list into a
    sandbox call; a shared mutable would leak cross-call."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        a = mod.proxy_hosts_for_semgrep()
        b = mod.proxy_hosts_for_semgrep()
    assert a == b
    assert a is not b
    a.append("mutation.example.com")
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        c = mod.proxy_hosts_for_semgrep()
    assert not _has_host(c, "mutation.example.com")


# ---------------------------------------------------------------------
# Override layer
# ---------------------------------------------------------------------


def test_override_takes_precedence(override_config):
    """Override config beats default — operator on Semgrep
    self-hosted / corporate registry mirror."""
    override_config({"hosts": ["semgrep.corp.example.com"]})
    hosts = mod.proxy_hosts_for_semgrep()
    assert hosts == ["semgrep.corp.example.com"]


def test_override_replaces_does_not_extend(override_config):
    """The override REPLACES rather than extending — operator on
    self-hosted typically wants to ban public Semgrep (no rule
    leakage to public registry)."""
    override_config({"hosts": ["semgrep.corp.example.com"]})
    hosts = mod.proxy_hosts_for_semgrep()
    assert not _has_host(hosts, "semgrep.dev")
    assert hosts == ["semgrep.corp.example.com"]


def test_override_dedupes_and_strips_garbage(override_config):
    """Operator-edited config; tolerate hand-edit accidents."""
    override_config({"hosts": [
        "semgrep.corp.example.com",
        "",                                  # empty — dropped
        "semgrep.corp.example.com",          # duplicate — dropped
        123,                                 # non-string — dropped
        "mirror.corp.example.com",
    ]})
    hosts = mod.proxy_hosts_for_semgrep()
    assert hosts == ["semgrep.corp.example.com",
                     "mirror.corp.example.com"]


def test_empty_override_falls_back_to_default(override_config):
    """``{"hosts": []}`` falls through to default rather than
    producing a deny-all allowlist."""
    override_config({"hosts": []})
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")


def test_override_missing_hosts_key_falls_back(override_config):
    """Schema mismatch — treat as no override, not deny-all."""
    override_config({"semgrep": ["semgrep.dev"]})
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")
    assert len(hosts) == 4


def test_override_malformed_json_falls_back(override_config):
    """Corrupted JSON — degrade silently to default."""
    mod._OVERRIDE_CONFIG_PATH.write_text(
        "{not valid json", encoding="utf-8",
    )
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")


def test_override_non_utf8_falls_back(override_config):
    """Operator pointed override path at a binary by mistake — must
    not crash the scanner spawn."""
    mod._OVERRIDE_CONFIG_PATH.write_bytes(
        b"\xff\xfe\x00\x00 not utf-8",
    )
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value=None):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")


# ---------------------------------------------------------------------
# Calibrated layer
# ---------------------------------------------------------------------


def _profile(proxy_hosts):
    """Stub object matching the SandboxProfile shape this module
    reads (only ``proxy_hosts`` is consulted)."""
    obj = mock.Mock()
    obj.proxy_hosts = proxy_hosts
    return obj


def test_calibrated_proxy_hosts_used_when_populated():
    """Operator ran a network-engaging probe → calibrated hosts win
    over the static default."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch.object(mod, "_calibrated_profile",
                           return_value=_profile(
                               ["semgrep.snapshot.example.com"])):
        hosts = mod.proxy_hosts_for_semgrep()
    assert hosts == ["semgrep.snapshot.example.com"]


def test_calibrated_empty_proxy_hosts_falls_through_to_default():
    """``--version`` calibration captures no network — falls through."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch.object(mod, "_calibrated_profile",
                           return_value=_profile([])):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")
    assert len(hosts) == 4


def test_calibrated_load_failure_falls_through_to_default():
    """Calibration raising (RuntimeError, OSError, etc.) must NOT
    propagate to the scanner — fall through cleanly."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=RuntimeError("observe-mode unavailable"),
         ):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")
    assert len(hosts) == 4


def test_calibrated_timeout_falls_through_to_default():
    """``subprocess.TimeoutExpired`` from the calibration probe must
    not crash the scanner. Empirically observed for some tools on
    cold systems where ``--version`` exceeds 20s under sandbox."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=subprocess.TimeoutExpired(
                ["semgrep", "--version"], 20,
            ),
         ):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")


def test_calibrated_filenotfound_falls_through_to_default():
    """Binary deleted between which() and probe (semgrep
    self-update race)."""
    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=FileNotFoundError("/fake/semgrep"),
         ):
        hosts = mod.proxy_hosts_for_semgrep()
    assert _has_host(hosts, "semgrep.dev")


def test_calibrate_per_process_memo_avoids_repeat_loads():
    """Multiple scanner spawns during one /scan should hit the
    in-memory memo, not re-stat the on-disk cache file each time."""
    call_count = [0]

    def _counting_load(*args, **kwargs):
        call_count[0] += 1
        return _profile([])

    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_counting_load,
         ):
        for _ in range(5):
            mod.proxy_hosts_for_semgrep()

    assert call_count[0] == 1, (
        f"expected 1 calibrate call across 5 invocations, "
        f"got {call_count[0]} — memoisation broke"
    )


def test_calibration_includes_documented_env_keys():
    """``SEMGREP_APP_TOKEN`` / ``SEMGREP_RULES`` /
    ``SEMGREP_RULES_CACHE`` must be part of the calibrate cache key
    so a binary used with two configs gets two distinct entries."""
    captured = {}

    def _capture_load(bin_path, **kwargs):
        captured.update(kwargs)
        return _profile([])

    with mock.patch.object(mod, "_resolve_semgrep_bin",
                           return_value="/fake/semgrep"), \
         mock.patch(
            "core.sandbox.calibrate.load_or_calibrate",
            side_effect=_capture_load,
         ):
        mod.proxy_hosts_for_semgrep()

    env_keys = tuple(captured.get("env_keys", ()))
    assert "SEMGREP_APP_TOKEN" in env_keys
    assert "SEMGREP_RULES" in env_keys
    assert "SEMGREP_RULES_CACHE" in env_keys


# ---------------------------------------------------------------------
# scanner.py wiring
# ---------------------------------------------------------------------


def test_scanner_imports_proxy_hosts_for_semgrep():
    """Scanner module imports the helper at the call site (deferred
    import to avoid heavy load at module-import time)."""
    scanner_path = (
        __import__("pathlib").Path(__file__).resolve()
        .parent.parent / "scanner.py"
    )
    text = scanner_path.read_text(encoding="utf-8")
    assert "proxy_hosts_for_semgrep" in text


def test_scanner_no_longer_hardcodes_semgrep_hosts():
    """Migration pin — if a future change reverts the call site to
    a hardcoded list, this test catches it."""
    scanner_path = (
        __import__("pathlib").Path(__file__).resolve()
        .parent.parent / "scanner.py"
    )
    text = scanner_path.read_text(encoding="utf-8")
    # The historical hardcoded list shape — looking for a literal
    # tuple/list of the four hosts together.
    assert 'proxy_hosts=["semgrep.dev", "registry.semgrep.dev"' \
        not in text, (
            "scanner.py reverted to hardcoded semgrep proxy_hosts; "
            "should route through proxy_hosts_for_semgrep()"
        )
