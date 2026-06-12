"""Tests for :mod:`cve_env.tools.arch`."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from cve_env.tools.arch import HostArch, arch_decide, detect_host_arch


def test_host_arch_docker_platform() -> None:
    assert HostArch(arch="arm64", os="darwin").docker_platform == "linux/arm64"
    assert HostArch(arch="amd64", os="linux").docker_platform == "linux/amd64"
    assert HostArch(arch="unknown", os="linux").docker_platform == "linux/amd64"


@patch("cve_env.tools.arch._platform")
def test_detect_host_arch_arm64_darwin(mock_plat: Any) -> None:
    detect_host_arch.cache_clear()
    mock_plat.machine.return_value = "arm64"
    mock_plat.system.return_value = "Darwin"
    with patch("cve_env.tools.arch.Path") as mock_path:
        mock_path.return_value.exists.return_value = True
        h = detect_host_arch()
    assert h.arch == "arm64"
    assert h.os == "darwin"
    assert h.rosetta_available is True
    detect_host_arch.cache_clear()


@patch("cve_env.tools.arch._platform")
def test_detect_host_arch_amd64_linux(mock_plat: Any) -> None:
    detect_host_arch.cache_clear()
    mock_plat.machine.return_value = "x86_64"
    mock_plat.system.return_value = "Linux"
    h = detect_host_arch()
    assert h.arch == "amd64"
    assert h.os == "linux"
    assert h.rosetta_available is False
    detect_host_arch.cache_clear()


def _manifest_response(*platforms: str) -> MagicMock:
    manifests = [
        {"platform": {"os": p.split("/")[0], "architecture": p.split("/")[1]}} for p in platforms
    ]
    return MagicMock(returncode=0, stdout=json.dumps({"manifests": manifests}), stderr="")


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_native_match(mock_run: Any) -> None:
    mock_run.return_value = _manifest_response("linux/arm64", "linux/amd64")
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("nginx:1.20", host=host)
    assert d.decision == "native"
    assert "linux/arm64" in d.supported_platforms


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_rosetta_fallback(mock_run: Any) -> None:
    mock_run.return_value = _manifest_response("linux/amd64")
    host = HostArch(arch="arm64", os="darwin", rosetta_available=True)
    d = arch_decide("amd64-only:1.0", host=host)
    assert d.decision == "rosetta_ok"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_no_match_triggers_build_from_source(mock_run: Any) -> None:
    mock_run.return_value = _manifest_response("linux/ppc64le")
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("ppc-only:1.0", host=host)
    assert d.decision == "build_from_source_required"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_rosetta_unavailable_forces_build(mock_run: Any) -> None:
    mock_run.return_value = _manifest_response("linux/amd64")
    host = HostArch(arch="arm64", os="darwin", rosetta_available=False)
    d = arch_decide("amd64-only:1.0", host=host)
    assert d.decision == "build_from_source_required"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_manifest_inspect_fails(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("nonexistent:x", host=host)
    assert d.decision == "error"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_single_arch_manifest(mock_run: Any) -> None:
    # Not a manifest list -- single-arch response.
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps({"config": {}, "architecture": "arm64", "os": "linux"}),
        stderr="",
    )
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("single-arch:1.0", host=host)
    assert d.decision == "native"
    assert "linux/arm64" in d.supported_platforms


# -- detect_host_arch: unknown machine (line 48) --------------------------


@patch("cve_env.tools.arch._platform")
def test_detect_host_arch_unknown_machine(mock_plat: Any) -> None:
    detect_host_arch.cache_clear()
    mock_plat.machine.return_value = "riscv64"
    mock_plat.system.return_value = "Linux"
    h = detect_host_arch()
    assert h.arch == "unknown"
    assert h.os == "linux"
    assert h.rosetta_available is False
    detect_host_arch.cache_clear()


# -- _manifest_inspect error/edge branches via arch_decide ----------------
#
# A manifest that can't be parsed into any usable platform makes
# ``_manifest_inspect`` return ``None`` → ``arch_decide`` yields ``error``.


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_invalid_json_is_error(mock_run: Any) -> None:
    """Non-JSON stdout → JSONDecodeError → None → error (lines 88-89)."""
    mock_run.return_value = MagicMock(returncode=0, stdout="not json at all", stderr="")
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("bad-json:1.0", host=host)
    assert d.decision == "error"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_top_level_not_dict_is_error(mock_run: Any) -> None:
    """Top-level JSON that is not a dict → no platforms → error (91->110)."""
    mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(["a", "b"]), stderr="")
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("list-json:1.0", host=host)
    assert d.decision == "error"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_skips_non_dict_manifest_entry(mock_run: Any) -> None:
    """A non-dict entry in ``manifests`` is skipped (line 96); the valid
    entry alongside it still drives the decision."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps(
            {
                "manifests": [
                    "junk-string-entry",
                    {"platform": {"os": "linux", "architecture": "arm64"}},
                ]
            }
        ),
        stderr="",
    )
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("mixed:1.0", host=host)
    assert d.decision == "native"
    assert d.supported_platforms == ["linux/arm64"]


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_skips_entry_with_non_dict_platform(mock_run: Any) -> None:
    """A manifest entry whose ``platform`` is not a dict is skipped
    (line 99); the only usable entry wins."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps(
            {
                "manifests": [
                    {"platform": "not-a-dict"},
                    {"platform": {"os": "linux", "architecture": "amd64"}},
                ]
            }
        ),
        stderr="",
    )
    host = HostArch(arch="amd64", os="linux")
    d = arch_decide("bad-platform:1.0", host=host)
    assert d.decision == "native"
    assert d.supported_platforms == ["linux/amd64"]


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_skips_entry_with_non_str_os_arch(mock_run: Any) -> None:
    """A platform whose os/arch are not both strings is not appended
    (102->94); with no usable entry the manifest yields error."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps(
            {"manifests": [{"platform": {"os": 123, "architecture": None}}]}
        ),
        stderr="",
    )
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("non-str-plat:1.0", host=host)
    assert d.decision == "error"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_dict_without_manifests_or_config_is_error(mock_run: Any) -> None:
    """A dict with neither a ``manifests`` list nor ``config``+
    ``architecture`` keys yields no platforms → error (104->110)."""
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps({"unrelated": "value"}), stderr=""
    )
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("empty-dict:1.0", host=host)
    assert d.decision == "error"


@patch("cve_env.utils.run.subprocess.run")
def test_arch_decide_single_arch_non_str_fields_is_error(mock_run: Any) -> None:
    """Single-arch manifest whose architecture is not a string is not
    appended (108->110) → error."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps({"config": {}, "architecture": 42}),
        stderr="",
    )
    host = HostArch(arch="arm64", os="linux")
    d = arch_decide("single-bad:1.0", host=host)
    assert d.decision == "error"
