"""Tests for ``packages/describe/tool_readiness.py`` — per-tool
readiness checks tailored to a target."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from packages.describe.target_shape import TargetShape
from packages.describe.tool_readiness import (
    ToolCheck,
    _check_binary_oracle,
    _check_codeql,
    _check_coccinelle,
    check_tool_readiness,
)


def _shape(**overrides) -> TargetShape:
    """Build a minimal TargetShape for tests; caller overrides
    fields relevant to the check under test."""
    base = {
        "target_path": Path("/tmp/test"),
        "languages": {"cpp": 100},
        "language_breakdown": {"cpp": 100.0},
        "primary_language": "cpp",
        "build_systems": {"cpp": "autotools"},
        "target_type": "c.userspace-daemon",
        "total_files": 100,
        "total_lines": 5000,
    }
    base.update(overrides)
    return TargetShape(**base)


# ---------------------------------------------------------------------------
# _check_codeql — target-specific build-deps check (host-level
# presence defers to /doctor).
# ---------------------------------------------------------------------------


class TestCheckCodeql:
    def test_missing_binary_defers_to_doctor(self):
        # Per the /describe scope boundary: host-level facts
        # belong in /doctor. /describe emits a deferral rather
        # than re-implementing install hints.
        with patch("shutil.which", return_value=None):
            result = _check_codeql(_shape())
        assert result.name == "CodeQL"
        assert result.status == "unknown"
        assert "deferred" in result.detail
        assert result.hint and "raptor doctor" in result.hint

    def test_present_binary_with_all_build_deps_returns_ok(self):
        def _which(cmd):
            # codeql + every autotools dep present.
            return "/usr/bin/" + cmd
        with patch("shutil.which", side_effect=_which):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="2.18.4",
            ):
                result = _check_codeql(_shape())
        assert result.status == "ok"
        assert result.version == "2.18.4"
        assert "build deps ok" in result.detail

    def test_present_binary_missing_autoreconf_warns(self):
        def _which(cmd):
            if cmd == "autoreconf":
                return None
            # Pretend apt is the installed PM (the test
            # machine's actual PM is irrelevant — we're pinning
            # the hint shape, not the host's PM).
            if cmd == "apt":
                return "/usr/bin/apt"
            return "/usr/bin/" + cmd
        from packages.describe.package_manager import (
            detect_package_manager,
        )
        detect_package_manager.cache_clear()
        with patch("shutil.which", side_effect=_which):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="2.18.4",
            ):
                result = _check_codeql(_shape())
        assert result.status == "warn"
        # Operator-actionable: names the missing dep + the build
        # system that needs it.
        assert "autoreconf" in result.detail
        assert "autotools" in result.detail
        # Hint includes the install verb + the apt package name.
        assert result.hint and "apt install" in result.hint
        assert "autoconf" in result.hint  # apt package name

    def test_check_uses_libtoolize_not_libtool(self):
        # Pin the libtoolize-vs-libtool fix. The Debian
        # ``libtool`` package ships ``libtoolize`` as the
        # bootstrap binary autoreconf actually invokes; a bare
        # ``libtool`` command isn't always present even when
        # the package is fully installed. Pre-fix the check
        # spuriously warned "DB build needs libtool" on
        # systems where the package was installed but the bare
        # ``libtool`` binary wasn't.
        from packages.describe.tool_readiness import _BUILD_SYSTEM_DEPS
        assert "libtoolize" in _BUILD_SYSTEM_DEPS["autotools"]
        assert "libtool" not in _BUILD_SYSTEM_DEPS["autotools"]
        # Install-advice registry resolves libtoolize → ``libtool``
        # package on every PM (that's what ships libtoolize).
        from packages.describe.package_manager import _INSTALL_ADVICE
        adv = _INSTALL_ADVICE["libtoolize"]
        assert adv.pm_packages
        assert adv.pm_packages.get("apt") == "libtool"
        assert adv.pm_packages.get("dnf") == "libtool"
        assert adv.pm_packages.get("brew") == "libtool"


# ---------------------------------------------------------------------------
# _check_coccinelle
# ---------------------------------------------------------------------------


class TestCheckCoccinelle:
    def test_missing_binary_defers_to_doctor(self):
        with patch("shutil.which", return_value=None):
            result = _check_coccinelle(_shape())
        assert result.status == "unknown"
        assert "deferred" in result.detail
        assert result.hint and "raptor doctor" in result.hint

    def test_c_target_returns_ok(self):
        with patch("shutil.which", return_value="/usr/bin/spatch"):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="1.3.0",
            ):
                result = _check_coccinelle(_shape(primary_language="cpp"))
        assert result.status == "ok"
        assert "applicable" in result.detail

    def test_python_target_warns_about_zero_fire(self):
        # Cocci's shipped rule pack is C-only — honest "will
        # 0-fire" warning instead of pretending it works.
        with patch("shutil.which", return_value="/usr/bin/spatch"):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="1.3.0",
            ):
                result = _check_coccinelle(
                    _shape(primary_language="python"),
                )
        assert result.status == "warn"
        assert "C-only" in result.detail
        assert "0 rules" in result.detail


# ---------------------------------------------------------------------------
# _check_binary_oracle — native-only, build-artefact-aware
# ---------------------------------------------------------------------------


class TestCheckBinaryOracle:
    def test_python_target_returns_none(self):
        # Binary oracle doesn't apply to managed-runtime languages.
        result = _check_binary_oracle(_shape(primary_language="python"))
        assert result is None

    def test_native_target_no_artefacts_warns(self, tmp_path):
        shape = _shape(target_path=tmp_path, primary_language="cpp")
        result = _check_binary_oracle(shape)
        assert result is not None
        assert result.status == "warn"
        assert "after build" in result.detail

    def test_native_target_with_build_dir_ok(self, tmp_path):
        (tmp_path / "build").mkdir()
        shape = _shape(target_path=tmp_path, primary_language="cpp")
        result = _check_binary_oracle(shape)
        assert result is not None
        assert result.status == "ok"
        assert "build artefacts" in result.detail


# ---------------------------------------------------------------------------
# Scope boundary: /describe does NOT check LLM configuration
# (host-level — /doctor's domain). Test that the helper is gone
# so a future drift back into this scope fails loudly.
# ---------------------------------------------------------------------------


class TestNoLlmCheckByDesign:
    def test_no_check_llm_function_exported(self):
        # /describe and /doctor have separate concerns; LLM
        # configuration is host-level and belongs in /doctor.
        # If a future change re-introduces an LLM check here,
        # update this test consciously.
        from packages.describe import tool_readiness as tr
        assert not hasattr(tr, "_check_llm"), (
            "tool_readiness._check_llm was reinstated. LLM "
            "config is host-level; /doctor owns it. Update "
            "the test only if the scope boundary changed."
        )

    def test_top_level_checks_exclude_llm(self):
        # The aggregate check list should NOT include any
        # "LLM dispatcher" entry — /describe focuses on target-
        # applicability only.
        with patch("shutil.which", return_value="/usr/bin/mock"):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="1.0",
            ):
                checks = check_tool_readiness(_shape())
        names = [c.name for c in checks]
        assert "LLM dispatcher" not in names


# ---------------------------------------------------------------------------
# check_tool_readiness — top-level integration
# ---------------------------------------------------------------------------


class TestStatusEnum:
    """Pin the ``status`` enum + renderer symbol-map alignment
    so a new status added in one place fails loudly if the
    other isn't updated. Downstream JSON consumers will rely
    on the set membership."""

    def test_renderer_symbol_map_covers_every_status(self):
        # If a new status is added to the contract, the renderer's
        # symbol map in packages/describe/report.py:_STATUS_SYMBOL
        # needs an entry too. This test fails loudly when they
        # drift.
        from packages.describe.report import _STATUS_SYMBOL
        known = {"ok", "warn", "fail", "unknown"}
        assert set(_STATUS_SYMBOL.keys()) == known, (
            f"_STATUS_SYMBOL keys drifted from the status enum. "
            f"Expected {known}; got {set(_STATUS_SYMBOL.keys())}."
        )


class TestCheckToolReadiness:
    def test_returns_list_of_tool_checks(self):
        # Smoke: top-level helper returns a non-empty list of
        # ToolCheck instances covering the target-applicability
        # surface (codeql build-deps + cocci language + binary
        # oracle). Per-tool semantics covered above.
        with patch("shutil.which", return_value="/usr/bin/mock"):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="1.0",
            ):
                checks = check_tool_readiness(_shape())
        # Three target-applicability checks (codeql + cocci +
        # binary-oracle for native targets).
        assert len(checks) == 3
        assert all(isinstance(c, ToolCheck) for c in checks)
        for c in checks:
            assert c.name
            assert c.status in ("ok", "warn", "fail", "unknown")
        # Host-level checks (LLM dispatcher) MUST NOT appear here.
        names = [c.name for c in checks]
        assert "LLM dispatcher" not in names

    def test_python_target_omits_binary_oracle(self):
        # Binary oracle returns None for managed-runtime targets;
        # caller filters it out.
        with patch("shutil.which", return_value="/usr/bin/mock"):
            with patch(
                "packages.describe.tool_readiness._bin_version",
                return_value="1.0",
            ):
                checks = check_tool_readiness(
                    _shape(primary_language="python",
                           languages={"python": 50},
                           language_breakdown={"python": 100.0},
                           build_systems={"python": "poetry"}),
                )
        names = [c.name for c in checks]
        assert "Binary oracle" not in names
