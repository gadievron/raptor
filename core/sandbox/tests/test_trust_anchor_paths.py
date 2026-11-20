"""The pwd-derived trust anchors ignore environment steering.

Three on-disk locations gate consent and integrity decisions — the
telemetry MAC key (core.sandbox.telemetry_mac), the WSL host-consent
marker (core.sandbox.host_consent), and the calibration profile cache
(core.sandbox.calibrate). $HOME and $XDG_DATA_HOME are on
SAFE_ENV_ALLOWLIST and therefore survive get_safe_env() into worker
children, so an env-derived anchor would let a composed environment
relocate the trust root (plant a marker, swap the MAC key, feed a
poisoned profile cache). These tests pin the contract: every anchor
derives from the passwd database for the current euid and is inert to
$HOME / $XDG_DATA_HOME / $XDG_CACHE_HOME.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from core.sandbox import calibrate as cal
from core.sandbox import host_consent as hc
from core.sandbox import telemetry_mac as tm

# Captured at import (collection) time, BEFORE the per-test autouse
# anchor pin in conftest.py swaps the seams for scratch paths — these
# are the real, shipping derivations.
_REAL_TM_DATA_HOME = tm._data_home
_REAL_HC_DATA_HOME = hc._data_home
_REAL_CACHE_DIR = cal._CACHE_DIR

_PASSWD_HOME = Path(pwd.getpwuid(os.geteuid()).pw_dir)


@pytest.fixture
def steered_env(monkeypatch, tmp_path):
    """An adversarially composed environment: every path-steering
    variable an allowlisted child could carry points into scratch."""
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "fake-data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "fake-cache"))
    return tmp_path


def test_telemetry_mac_anchor_is_passwd_derived(steered_env):
    assert _REAL_TM_DATA_HOME() == _PASSWD_HOME / ".local" / "share"


def test_host_consent_anchor_is_passwd_derived(steered_env):
    assert _REAL_HC_DATA_HOME() == _PASSWD_HOME / ".local" / "share"


def test_calibrate_cache_dir_is_passwd_derived(steered_env):
    # The cache dir is a module constant: it was computed at import,
    # long before this test's env steering — asserting under the
    # steered env documents that re-reading it can never move it.
    assert _REAL_CACHE_DIR == (
        _PASSWD_HOME / ".cache" / "raptor" / "sandbox-profiles"
    )


def test_env_steering_is_ignored_by_the_seams(steered_env):
    """The derivations consult only the passwd database — identical
    results with and without the hostile environment."""
    with_env = (_REAL_TM_DATA_HOME(), _REAL_HC_DATA_HOME())
    for var in ("HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        os.environ.pop(var, None)  # monkeypatch restores at teardown
    assert (_REAL_TM_DATA_HOME(), _REAL_HC_DATA_HOME()) == with_env


def test_leaf_paths_build_on_the_anchor(monkeypatch, tmp_path):
    """marker_path() and _key_path() derive from the _data_home seam
    (one patch point steers every consumer, including the tamper
    marker's with_name derivation)."""
    base = tmp_path / "pinned"
    monkeypatch.setattr(hc, "_data_home", lambda: base)
    monkeypatch.setattr(tm, "_data_home", lambda: base)
    assert hc.marker_path() == base / "raptor" / hc._MARKER_NAME
    assert tm._key_path() == base / "raptor" / "telemetry-mac.key"
    assert tm.tamper_marker_path().parent == base / "raptor"
