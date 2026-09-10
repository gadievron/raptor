from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / ".devcontainer" / "Dockerfile"
INSTALLER = ROOT / "containers" / "install-all-tools-native.sh"
MANIFEST = ROOT / "containers" / "all-tools-manifest.json"
VERIFIER = ROOT / "containers" / "verify-all-tools.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


all_tools = _load_module("browser_rust_fuzz_verifier_under_test", VERIFIER)


def _write_manifest(tmp_path: Path, manifest: dict) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_playwright_uses_shared_path_and_launches_as_runtime_user() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    browser_env = "ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright"
    browser_install = "python -m playwright install --with-deps chromium"
    all_tools_stage = "FROM raptor-base AS raptor-all-tools-build"

    assert dockerfile.index(browser_env) < dockerfile.index(browser_install)
    install_start = dockerfile.index(
        'RUN install -d -m 0755 -o root -g vscode "${PLAYWRIGHT_BROWSERS_PATH}"'
    )
    install_end = dockerfile.index("# CLAUDE CLI", install_start)
    install_block = dockerfile[install_start:install_end]
    assert 'chown -R root:vscode "${PLAYWRIGHT_BROWSERS_PATH}"' in install_block
    assert 'chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}"' in install_block

    base_user = dockerfile.index("USER vscode")
    browser_smoke = dockerfile.index("raptor-playwright-smoke", base_user)
    assert base_user < browser_smoke < dockerfile.index(all_tools_stage)

    all_tools_start = dockerfile.index(all_tools_stage)
    all_tools_user = dockerfile.index("USER vscode", all_tools_start)
    runtime_probe = dockerfile.index(
        "RUN raptor-verify-all-tools --runtime-probes",
        all_tools_user,
    )
    assert all_tools_user < runtime_probe
    assert "FROM raptor-base AS raptor-devcontainer" in dockerfile
    assert "FROM raptor-all-tools-build AS raptor-all-tools" in dockerfile


def test_cargo_fuzz_uses_snapshot_nightly_and_vendored_offline_fixture() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    installer = INSTALLER.read_text(encoding="utf-8")
    verifier = VERIFIER.read_text(encoding="utf-8")
    rust = manifest["tools"]["rust"]

    assert manifest["snapshot_date"] == "2026-09-08"
    assert rust["version"] == "1.98.1"
    assert rust["nightly_toolchain"] == "nightly-2026-09-08"
    assert rust["nightly_version"] == (
        "1.100.0-nightly (cea272fa3 2026-09-07)"
    )
    assert '--default-toolchain "$rust_version"' in installer
    assert 'rustup toolchain install \\\n    "$rust_nightly" --profile minimal' in (
        installer
    )

    wrapper_start = installer.index("cat > /usr/local/bin/cargo-fuzz")
    wrapper_end = installer.index("chmod 0755 /usr/local/bin/cargo-fuzz")
    wrapper = installer[wrapper_start:wrapper_end]
    assert 'export RUSTUP_TOOLCHAIN="$rust_nightly"' in wrapper
    assert 'exec /opt/cargo/bin/cargo-fuzz "\\$@"' in wrapper
    all_tools_path = next(
        line
        for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if line.startswith('ENV PATH="/usr/lib/jvm/temurin-21-jdk/bin:')
    )
    assert all_tools_path.index("/usr/local/bin") < all_tools_path.index(
        "/opt/cargo/bin"
    )

    assert "/usr/local/share/raptor/cargo-fuzz-smoke" in installer
    assert "/usr/local/share/raptor/cargo-fuzz-vendor" in installer
    assert "/opt/cargo/bin/cargo vendor --locked" in installer
    assert '"CARGO_NET_OFFLINE": "true"' in verifier
    assert "sanitizer=address" in verifier
    assert "/opt/ms-playwright" in manifest["required_paths"]
    assert "/usr/local/share/raptor/cargo-fuzz-smoke" in (
        manifest["required_paths"]
    )
    assert "/usr/local/share/raptor/cargo-fuzz-vendor" in (
        manifest["required_paths"]
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "nightly_toolchain",
            "nightly",
            "Rust nightly toolchain must be date-pinned",
        ),
        (
            "nightly_toolchain",
            "nightly-2026-09-07",
            "Rust nightly toolchain must be date-pinned",
        ),
        (
            "nightly_version",
            "1.100.0-nightly",
            "Rust nightly_version must record the exact nightly rustc",
        ),
    ],
)
def test_manifest_rejects_unpinned_nightly(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["tools"]["rust"][field] = value

    with pytest.raises(ValueError, match=message):
        all_tools.load_manifest(_write_manifest(tmp_path, manifest))


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed")
def test_built_all_tools_image_runs_browser_and_fuzz_smokes_offline() -> None:
    image = os.environ.get("RAPTOR_BROWSER_RUST_FUZZ_TEST_IMAGE")
    if not image:
        pytest.skip(
            "set RAPTOR_BROWSER_RUST_FUZZ_TEST_IMAGE for the image runtime smoke"
        )

    result = subprocess.run(
        [
            "podman",
            "run",
            "--rm",
            "--network=none",
            image,
            "bash",
            "-lc",
            (
                'test "$(id -un)" = vscode '
                '&& test "$PLAYWRIGHT_BROWSERS_PATH" = /opt/ms-playwright '
                "&& rustc --version | grep -F 'rustc 1.98.1 ' "
                "&& raptor-verify-all-tools --runtime-probes"
            ),
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=600,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    assert (
        "all-tools runtime probes verified with nightly-2026-09-08"
        in output
    )
