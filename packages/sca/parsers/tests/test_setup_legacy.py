"""Tests for the legacy setuptools surfaces: setup.cfg parser and the
setup.py visibility stub."""

from __future__ import annotations

import logging
from pathlib import Path

from packages.sca.parsers import capture_parse_failures
from packages.sca.parsers.setup_cfg import parse as parse_cfg
from packages.sca.parsers.setup_py import parse as parse_py


# ---------------------------------------------------------------------------
# setup.cfg
# ---------------------------------------------------------------------------

def _write_cfg(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "setup.cfg"
    p.write_text(body, encoding="utf-8")
    return p


def test_setup_cfg_install_requires(tmp_path: Path) -> None:
    body = (
        "[metadata]\n"
        "name = demo\n"
        "\n"
        "[options]\n"
        "install_requires =\n"
        "    requests>=2.0\n"
        "    packaging\n"
        "setup_requires =\n"
        "    setuptools-scm\n"
        "\n"
        "[options.extras_require]\n"
        "dev =\n"
        "    pytest>=7\n"
    )
    deps = {d.name: d for d in parse_cfg(_write_cfg(tmp_path, body))}
    assert deps["requests"].scope == "main"
    assert deps["packaging"].scope == "main"
    assert deps["setuptools-scm"].scope == "build"
    assert deps["pytest"].scope == "optional"
    assert all(d.ecosystem == "PyPI" for d in deps.values())


def test_setup_cfg_without_options_yields_nothing(tmp_path: Path) -> None:
    assert parse_cfg(_write_cfg(tmp_path, "[metadata]\nname = demo\n")) == []


def test_setup_cfg_malformed_ini_returns_empty(tmp_path: Path) -> None:
    assert parse_cfg(_write_cfg(tmp_path, "not an ini [\n=broken\n")) == []


def test_setup_cfg_dispatch_via_registry(tmp_path: Path) -> None:
    from packages.sca.parsers import _resolve
    p = _write_cfg(tmp_path, "[options]\ninstall_requires =\n    x\n")
    fn = _resolve(p)
    assert fn is not None
    assert fn.__module__.endswith("setup_cfg")


# ---------------------------------------------------------------------------
# setup.py visibility stub
# ---------------------------------------------------------------------------

def test_setup_py_with_requires_surfaces_parse_failure(
    tmp_path: Path, caplog,
) -> None:
    # setup.py is executable Python: no static extraction, but the
    # drop must be VISIBLE via the parse-failure counter instead of a
    # silent zero-dep result.
    p = tmp_path / "setup.py"
    p.write_text(
        "from setuptools import setup\n"
        'setup(install_requires=["requests"])\n',
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        with capture_parse_failures() as failures:
            assert parse_py(p) == []
    assert len(failures) == 1
    assert failures[0].path == p
    assert "not extracted" in failures[0].reason


def test_setup_py_shim_stays_quiet(tmp_path: Path) -> None:
    # Other direction: the common PEP 517 shim declares nothing —
    # no deps are being dropped, so no warning noise.
    p = tmp_path / "setup.py"
    p.write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    with capture_parse_failures() as failures:
        assert parse_py(p) == []
    assert failures == []


def test_setup_py_dispatch_via_registry(tmp_path: Path) -> None:
    from packages.sca.parsers import _resolve
    p = tmp_path / "setup.py"
    p.write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    fn = _resolve(p)
    assert fn is not None
    assert fn.__module__.endswith("setup_py")
