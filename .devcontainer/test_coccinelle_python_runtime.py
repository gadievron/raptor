from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "containers" / "install-all-tools-native.sh"
DOUBLE_FREE_RULE = ROOT / "engine" / "coccinelle" / "rules" / "double_free.cocci"


def test_installer_enables_python_314_and_runs_real_smoke() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert "--without-python" not in installer
    assert "--enable-python=yes" in installer
    assert '--with-python="$python_bin"' in installer
    assert 'PYVER="$python_version"' in installer
    assert '"$python_config" --embed --ldflags' in installer
    assert "pkg-config --libs python-%d.%d-embed" in installer
    assert "/etc/ld.so.conf.d/raptor-python.conf" in installer
    assert "ldconfig" in installer
    assert "verify_coccinelle_python_runtime" in installer
    assert "COCCIRESULT:coccinelle-python-runtime:" in installer
    assert "spatch" in installer


def test_shipped_double_free_rule_contains_python_result_contract() -> None:
    rule = DOUBLE_FREE_RULE.read_text(encoding="utf-8")

    assert "@script:python@" in rule
    assert "COCCIRESULT:" in rule
    assert '"rule": "double_free"' in rule


def test_installer_shell_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed")
def test_built_image_runs_shipped_python_rule(tmp_path: Path) -> None:
    image = os.environ.get("RAPTOR_COCCINELLE_TEST_IMAGE")
    if not image:
        pytest.skip("set RAPTOR_COCCINELLE_TEST_IMAGE for the image-level smoke")

    source = tmp_path / "double.c"
    source.write_text(
        """void bug(char *p) {
    free(p);
    free(p);
}
""",
        encoding="utf-8",
    )
    source.chmod(0o644)

    result = subprocess.run(
        [
            "podman",
            "run",
            "--rm",
            "--mount",
            f"type=bind,src={ROOT},dst=/workspaces/raptor,relabel=shared",
            "--mount",
            f"type=bind,src={source},dst=/target.c,relabel=shared",
            image,
            "spatch",
            "--sp-file",
            "/workspaces/raptor/engine/coccinelle/rules/double_free.cocci",
            "/target.c",
            "--no-show-diff",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    assert "COCCIRESULT:" in output
    assert '"rule": "double_free"' in output
