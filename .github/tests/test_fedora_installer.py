"""Hermetic tests for the Fedora host bootstrap script."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "packaging" / "fedora" / "install-raptor-fedora-tools.sh"


class FedoraInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.fixture_repo = self.root / "repo with spaces"
        self.fake_bin = self.root / "fake-bin"
        self.venv = self.root / "project venv"
        self.os_release = self.root / "os-release"
        self.dnf_log = self.root / "dnf.log"

        for relative in (
            "raptor.py",
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-grammars.txt",
            "packages/web/requirements.txt",
            ".devcontainer/requirements-all-optional.txt",
        ):
            path = self.fixture_repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

        self.fake_bin.mkdir()
        fake_dnf = self.fake_bin / "dnf"
        fake_dnf.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -Eeuo pipefail
                printf '%q ' "$@" >> "$DNF_LOG"
                printf '\\n' >> "$DNF_LOG"
                [[ " $* " == *" repoquery "* ]] || {
                    printf 'unexpected non-query dnf invocation\\n' >&2
                    exit 90
                }

                skip_next=0
                for argument in "$@"; do
                    if ((skip_next)); then
                        skip_next=0
                        continue
                    fi
                    case "$argument" in
                        -q|repoquery|--available)
                            continue
                            ;;
                        --qf)
                            skip_next=1
                            continue
                            ;;
                    esac
                    if [[ "$argument" != "${FEDORA_TEST_UNAVAILABLE:-}" ]]; then
                        printf '%s\\n' "$argument"
                    fi
                done
                """
            ),
            encoding="utf-8",
        )
        fake_dnf.chmod(0o755)
        self.write_os_release("fedora", "44", "Fedora Linux 44 (Test)")

    def write_os_release(self, distro_id: str, version: str, pretty: str):
        self.os_release.write_text(
            f'ID="{distro_id}"\n'
            f'VERSION_ID="{version}"\n'
            f'PRETTY_NAME="{pretty}"\n',
            encoding="utf-8",
        )

    def run_installer(
        self,
        *arguments: str,
        architecture: str = "x86_64",
        effective_uid: int = 1000,
        node_version: str | None = "v22.0.0",
        npm_present: bool = True,
        npm_version: str = "10.0.0",
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "DNF_LOG": str(self.dnf_log),
                "FEDORA_TEST_UNAVAILABLE": "rr",
                "FEDORA_TEST_ARCHITECTURE": architecture,
                "FEDORA_TEST_EUID": str(effective_uid),
                "FEDORA_TEST_NODE_PRESENT": "1" if node_version else "0",
                "FEDORA_TEST_NODE_VERSION": node_version or "",
                "FEDORA_TEST_NPM_PRESENT": "1" if npm_present else "0",
                "FEDORA_TEST_NPM_VERSION": npm_version,
                "HOME": str(self.root),
                "PATH": f"{self.fake_bin}:{env.get('PATH', '')}",
                "RAPTOR_FEDORA_INSTALLER_OS_RELEASE_FILE": str(self.os_release),
            }
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                textwrap.dedent(
                    """\
                    installer=$1
                    shift
                    source "$installer"
                    get_effective_uid() {
                        printf '%s\\n' "$FEDORA_TEST_EUID"
                    }
                    get_host_architecture() {
                        printf '%s\\n' "$FEDORA_TEST_ARCHITECTURE"
                    }
                    find_host_executable() {
                        case "$1" in
                            node)
                                [[ "$FEDORA_TEST_NODE_PRESENT" == 1 ]] || return 1
                                printf '/test/bin/node\\n'
                                ;;
                            npm)
                                [[ "$FEDORA_TEST_NPM_PRESENT" == 1 ]] || return 1
                                printf '/test/bin/npm\\n'
                                ;;
                            *)
                                return 1
                                ;;
                        esac
                    }
                    read_host_node_version() {
                        printf '%s\\n' "$FEDORA_TEST_NODE_VERSION"
                    }
                    read_host_npm_version() {
                        printf '%s\\n' "$FEDORA_TEST_NPM_VERSION"
                    }
                    main "$@"
                    """
                ),
                "fedora-installer-test",
                str(INSTALLER),
                "--repo",
                str(self.fixture_repo),
                "--venv",
                str(self.venv),
                *arguments,
            ],
            capture_output=True,
            check=False,
            env=env,
            text=True,
            timeout=20,
        )

    def test_script_is_executable_and_valid_bash(self):
        mode = INSTALLER.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR)
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_help_lists_supported_options_without_querying_dnf(self):
        result = subprocess.run(
            [str(INSTALLER), "--help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        for option in (
            "--repo",
            "--venv",
            "--minimal",
            "--no-python",
            "--no-browser",
            "--dry-run",
            "--help",
        ):
            self.assertIn(option, result.stdout)

    def test_full_dry_run_separates_rpms_and_python_dependencies(self):
        result = self.run_installer("--dry-run")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Native RPM dependency plan:", result.stdout)
        self.assertIn("Python dependency plan:", result.stdout)
        self.assertIn("requirements-dev.txt", result.stdout)
        self.assertIn("requirements-grammars.txt", result.stdout)
        self.assertIn("packages/web/requirements.txt", result.stdout)
        self.assertIn(
            ".devcontainer/requirements-all-optional.txt", result.stdout
        )
        self.assertIn("semgrep==1.172.0", result.stdout)
        self.assertIn("atheris==3.1.0", result.stdout)
        self.assertIn("orjson==3.11.9", result.stdout)
        self.assertNotIn("orjson==3.12.0", result.stdout)
        self.assertIn("Playwright Chromium will be installed", result.stdout)
        self.assertIn("rr", result.stdout)
        self.assertIn("unavailable", result.stdout.lower())
        self.assertFalse(self.venv.exists())

        plan, manual = result.stdout.split(
            "Upstream-only or manual tools not installed by this script:", 1
        )
        self.assertNotIn("angr==", plan)
        self.assertIn("angr", manual)
        self.assertIn("z3", manual)
        self.assertIn("does not request, read, store, or print credentials", manual)

        dnf_calls = self.dnf_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(dnf_calls), 1)
        self.assertIn("repoquery", dnf_calls[0])
        self.assertNotIn(" install ", f" {dnf_calls[0]} ")
        install_line = next(
            line
            for line in result.stdout.splitlines()
            if "dnf install -y" in line
        )
        self.assertNotIn(" rr ", f" {install_line} ")

    def test_minimal_dry_run_omits_full_mode_dependencies(self):
        result = self.run_installer("--minimal", "--dry-run")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("requirements-dev.txt", result.stdout)
        self.assertIn("semgrep==1.172.0", result.stdout)
        self.assertNotIn("requirements-grammars.txt", result.stdout)
        self.assertNotIn("packages/web/requirements.txt", result.stdout)
        self.assertNotIn("requirements-all-optional.txt", result.stdout)
        self.assertNotIn("playwright install chromium", result.stdout)
        self.assertNotIn("nuclei", self.dnf_log.read_text(encoding="utf-8"))
        self.assertFalse(self.venv.exists())

    def test_full_node_22_uses_existing_tools_and_omits_node_24_rpms(self):
        result = self.run_installer("--dry-run", node_version="v22.12.0")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("using existing Node.js v22.12.0", result.stdout)
        self.assertIn("with npm 10.0.0", result.stdout)
        self.assertIn("Fedora Node.js 24 RPMs omitted", result.stdout)

        dnf_query = self.dnf_log.read_text(encoding="utf-8")
        install_line = next(
            line
            for line in result.stdout.splitlines()
            if "dnf install -y" in line
        )
        for package in ("nodejs24", "nodejs24-bin", "nodejs24-npm"):
            self.assertNotIn(package, dnf_query)
            self.assertNotIn(package, install_line)

    def test_full_without_node_requests_node_24_rpms(self):
        result = self.run_installer(
            "--dry-run", node_version=None, npm_present=False
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("no existing Node.js or npm detected", result.stdout)
        self.assertIn("requesting Fedora Node.js 24 RPMs", result.stdout)

        dnf_query = self.dnf_log.read_text(encoding="utf-8")
        install_line = next(
            line
            for line in result.stdout.splitlines()
            if "dnf install -y" in line
        )
        for package in ("nodejs24", "nodejs24-bin", "nodejs24-npm"):
            self.assertIn(package, dnf_query)
            self.assertIn(package, install_line)

    def test_full_with_old_node_fails_without_changing_alternatives(self):
        result = self.run_installer("--dry-run", node_version="v20.19.5")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incompatible Node.js installation", result.stderr)
        self.assertIn("major 20", result.stderr)
        self.assertIn("major version >=22", result.stderr)
        self.assertIn("will not use dnf --allowerasing", result.stderr)
        self.assertIn("rpm -qf /test/bin/node /test/bin/npm", result.stderr)
        self.assertIn(
            "sudo dnf install nodejs24 nodejs24-bin nodejs24-npm",
            result.stderr,
        )
        self.assertFalse(self.dnf_log.exists())
        self.assertFalse(self.venv.exists())

    def test_full_aarch64_dry_run_reports_and_skips_atheris(self):
        result = self.run_installer("--dry-run", architecture="aarch64")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Host architecture: aarch64", result.stdout)
        self.assertIn(
            "Unavailable/skipped for architecture aarch64:", result.stdout
        )
        self.assertIn(
            "atheris==3.1.0 (unsupported on aarch64)", result.stdout
        )

        commands = result.stdout.split("Dry-run commands (not executed):", 1)[1]
        commands = commands.split(
            "Upstream-only or manual tools not installed by this script:", 1
        )[0]
        self.assertNotIn("atheris==3.1.0", commands)
        self.assertFalse(self.venv.exists())

    def test_no_browser_retains_web_packages_but_skips_download(self):
        result = self.run_installer("--no-browser", "--dry-run")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("packages/web/requirements.txt", result.stdout)
        self.assertIn("download disabled by --no-browser", result.stdout)
        self.assertNotIn(" -m playwright install chromium", result.stdout)
        self.assertFalse(self.venv.exists())

    def test_no_python_dry_run_has_no_venv_commands(self):
        self.venv.mkdir()
        marker = self.venv / "do-not-touch"
        marker.write_text("preserve", encoding="utf-8")
        result = self.run_installer("--no-python", "--dry-run")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Disabled by --no-python", result.stdout)
        self.assertIn("setup was skipped by --no-python", result.stdout)
        self.assertNotIn(" -m pip ", result.stdout)
        self.assertNotIn(" -m venv ", result.stdout)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_root_python_setup_is_rejected_before_repoquery(self):
        result = self.run_installer("--dry-run", effective_uid=0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not run this installer with sudo or as root", result.stderr)
        self.assertIn("Run it as your regular user", result.stderr)
        self.assertIn("--no-python", result.stderr)
        self.assertFalse(self.dnf_log.exists())
        self.assertFalse(self.venv.exists())

    def test_root_no_python_dry_run_remains_allowed(self):
        result = self.run_installer(
            "--no-python", "--dry-run", effective_uid=0
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Disabled by --no-python", result.stdout)
        dnf_install = next(
            line
            for line in result.stdout.splitlines()
            if "dnf install -y" in line
        )
        self.assertTrue(dnf_install.lstrip().startswith("dnf install -y"))
        self.assertNotIn("sudo", dnf_install)

    def test_non_fedora_host_fails_before_repoquery(self):
        self.write_os_release("ubuntu", "26.04", "Ubuntu 26.04")
        result = self.run_installer("--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires Fedora", result.stderr)
        self.assertFalse(self.dnf_log.exists())


if __name__ == "__main__":
    unittest.main()
