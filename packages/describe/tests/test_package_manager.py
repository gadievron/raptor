"""Tests for ``packages/describe/package_manager.py``."""

from __future__ import annotations

from unittest.mock import patch

from packages.describe import package_manager as pm_mod
from packages.describe.package_manager import (
    detect_package_manager,
    format_install_hint,
)


def _which_only(present_pms):
    """Return a shutil.which mock that finds the given PMs and
    nothing else."""
    def _which(cmd):
        return "/usr/bin/" + cmd if cmd in present_pms else None
    return _which


class TestDetectPackageManager:
    def setup_method(self):
        # Cached at module level — reset between tests.
        detect_package_manager.cache_clear()

    def test_apt_detected(self):
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            assert detect_package_manager() == "apt"

    def test_dnf_detected(self):
        with patch("shutil.which", side_effect=_which_only({"dnf"})):
            assert detect_package_manager() == "dnf"

    def test_pacman_detected(self):
        with patch("shutil.which", side_effect=_which_only({"pacman"})):
            assert detect_package_manager() == "pacman"

    def test_brew_detected(self):
        with patch("shutil.which", side_effect=_which_only({"brew"})):
            assert detect_package_manager() == "brew"

    def test_first_wins_when_multiple_pms_present(self):
        # System with both apt + brew installed (e.g. Homebrew on
        # Linux). Order in _KNOWN_PMS places apt first because
        # system tool deps typically come from the native PM,
        # not the user-local one.
        with patch("shutil.which", side_effect=_which_only({"apt", "brew"})):
            assert detect_package_manager() == "apt"

    def test_no_pm_returns_none(self):
        with patch("shutil.which", side_effect=_which_only(set())):
            assert detect_package_manager() is None


class TestFormatInstallHint:
    def setup_method(self):
        detect_package_manager.cache_clear()

    def test_apt_hint(self):
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            assert format_install_hint(["libtool"]) == "sudo apt install libtool"

    def test_dnf_hint(self):
        with patch("shutil.which", side_effect=_which_only({"dnf"})):
            assert format_install_hint(["libtool"]) == "sudo dnf install libtool"

    def test_yum_hint_uses_yum(self):
        with patch("shutil.which", side_effect=_which_only({"yum"})):
            assert format_install_hint(["libtool"]) == "sudo yum install libtool"

    def test_pacman_hint(self):
        with patch("shutil.which", side_effect=_which_only({"pacman"})):
            assert format_install_hint(["libtool"]) == "sudo pacman -S libtool"

    def test_zypper_hint(self):
        with patch("shutil.which", side_effect=_which_only({"zypper"})):
            assert (
                format_install_hint(["libtool"])
                == "sudo zypper install libtool"
            )

    def test_apk_hint(self):
        with patch("shutil.which", side_effect=_which_only({"apk"})):
            assert format_install_hint(["libtool"]) == "sudo apk add libtool"

    def test_brew_hint_omits_sudo(self):
        # brew runs as the calling user — sudo would actually
        # cause problems with permissions on the cellar.
        with patch("shutil.which", side_effect=_which_only({"brew"})):
            assert format_install_hint(["libtool"]) == "brew install libtool"

    def test_multi_package_install(self):
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            assert (
                format_install_hint(["autoconf", "automake", "libtool"])
                == "sudo apt install autoconf automake libtool"
            )

    def test_no_pm_generic_fallback(self):
        with patch("shutil.which", side_effect=_which_only(set())):
            hint = format_install_hint(["libtool"])
            assert "libtool" in hint
            assert "system package manager" in hint

    def test_mac_caveat_appended_on_darwin(self, monkeypatch):
        # gdb on macOS: install command works (brew install gdb)
        # but the runtime needs codesigning. The caveat appears
        # only on Darwin; Linux operators (the more common case)
        # don't see the noise.
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        with patch(
            "packages.describe.package_manager._platform.system",
            return_value="Darwin",
        ):
            with patch(
                "shutil.which",
                side_effect=_which_only({"brew"}),
            ):
                hint = format_install_advice("gdb")
        assert "brew install gdb" in hint
        assert "codesigning" in hint
        assert "lldb" in hint

    def test_mac_caveat_suppressed_on_linux(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        with patch(
            "packages.describe.package_manager._platform.system",
            return_value="Linux",
        ):
            with patch(
                "shutil.which",
                side_effect=_which_only({"apt"}),
            ):
                hint = format_install_advice("gdb")
        assert "apt install gdb" in hint
        # No mac caveat noise for Linux operators.
        assert "codesigning" not in hint
        assert "macOS" not in hint

    def test_afl_fuzz_mac_caveat_for_apple_silicon(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        with patch(
            "packages.describe.package_manager._platform.system",
            return_value="Darwin",
        ):
            with patch(
                "shutil.which",
                side_effect=_which_only({"brew"}),
            ):
                hint = format_install_advice("afl-fuzz")
        assert "brew install afl-fuzz" in hint
        assert "Apple Silicon" in hint

    def test_pipx_in_active_venv_uses_pip(self, monkeypatch):
        # In a venv, pip install works (no PEP 668 issue inside
        # the venv's site-packages). Operator gets the actually-
        # working command, not a pipx detour.
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.setenv("VIRTUAL_ENV", "/tmp/myvenv")
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            hint = format_install_advice("semgrep")
        assert hint.startswith("pip install semgrep")

    def test_pipx_in_active_conda_env_uses_conda(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setenv("CONDA_DEFAULT_ENV", "myenv")
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            hint = format_install_advice("semgrep")
        assert "conda install -c conda-forge semgrep" in hint

    def test_pipx_with_uv_present_uses_uv(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"uv", "apt"})):
            hint = format_install_advice("semgrep")
        assert hint.startswith("uv tool install semgrep")

    def test_pipx_present_uses_pipx(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"pipx", "apt"})):
            hint = format_install_advice("semgrep")
        assert hint.startswith("pipx install semgrep")

    def test_pipx_missing_chains_bootstrap_for_apt(self, monkeypatch):
        # Most-common Linux operator case: pipx not installed,
        # apt is the PM. Hint must chain the bootstrap with
        # ensurepath so the next command finds the binary.
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            hint = format_install_advice("semgrep")
        assert "sudo apt install pipx" in hint
        assert "pipx ensurepath" in hint
        assert "pipx install semgrep" in hint
        # Chain order: install pipx → ensurepath → install pkg.
        assert (
            hint.index("apt install pipx")
            < hint.index("pipx ensurepath")
            < hint.index("pipx install semgrep")
        )

    def test_pipx_missing_chains_bootstrap_for_brew(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"brew"})):
            hint = format_install_advice("semgrep")
        assert "brew install pipx" in hint
        assert "pipx install semgrep" in hint

    def test_pipx_missing_pacman_uses_python_pipx_package_name(
        self, monkeypatch,
    ):
        # Arch namespaces python packages under ``python-X``. Pin
        # the package name so a future PM-mapping change doesn't
        # accidentally suggest the non-existent bare ``pipx``.
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only({"pacman"})):
            hint = format_install_advice("semgrep")
        assert "sudo pacman -S python-pipx" in hint

    def test_pipx_no_pm_no_env_points_to_pipx_docs(self, monkeypatch):
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_DEFAULT_ENV", raising=False)
        with patch("shutil.which", side_effect=_which_only(set())):
            hint = format_install_advice("semgrep")
        # Operator-readable prose check rather than a hostname
        # fragment — ``py/incomplete-url-substring-sanitization``
        # false-positives on assertions like ``"pypa.io" in hint``
        # because the substring looks like a URL-allowlist check.
        # Same FP class as the trusted→short_circuit rename.
        assert "install pipx first" in hint
        assert "pipx install semgrep" in hint

    def test_venv_wins_over_conda(self, monkeypatch):
        # Both set (operator activated a venv inside a conda env).
        # VIRTUAL_ENV wins because it's the more-immediate active
        # context.
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        monkeypatch.setenv("VIRTUAL_ENV", "/tmp/v")
        monkeypatch.setenv("CONDA_DEFAULT_ENV", "myenv")
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            hint = format_install_advice("semgrep")
        assert hint.startswith("pip install semgrep")

    def test_tool_without_mac_caveat_renders_normally_on_mac(self, monkeypatch):
        # libtoolize has no mac_caveat — should render plain on
        # macOS too (no spurious dash-clause appears).
        from packages.describe.package_manager import (
            format_install_advice,
        )
        detect_package_manager.cache_clear()
        with patch(
            "packages.describe.package_manager._platform.system",
            return_value="Darwin",
        ):
            with patch(
                "shutil.which",
                side_effect=_which_only({"brew"}),
            ):
                hint = format_install_advice("libtoolize")
        assert hint == "brew install libtool"
        assert "macOS" not in hint

    def test_per_pm_override_applies(self, monkeypatch):
        # Synthetic per-PM override → resolves the binary to a
        # different package name on a specific PM.
        monkeypatch.setattr(
            pm_mod, "_PER_PM_PKG_OVERRIDES",
            {"libtool": {"dnf": "libtool-special"}},
        )
        with patch("shutil.which", side_effect=_which_only({"dnf"})):
            assert (
                format_install_hint(["libtool"])
                == "sudo dnf install libtool-special"
            )
        # And on a different PM, the override doesn't apply.
        # Cache cleared because the prior detection inside this
        # test pinned "dnf"; otherwise the lru_cache would
        # return dnf again.
        detect_package_manager.cache_clear()
        with patch("shutil.which", side_effect=_which_only({"apt"})):
            assert (
                format_install_hint(["libtool"])
                == "sudo apt install libtool"
            )
