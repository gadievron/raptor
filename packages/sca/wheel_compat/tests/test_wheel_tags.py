"""Tests for the PEP 425 wheel-tag parser."""

from __future__ import annotations

from packages.sca.platform_matrix.glibc_db import LibcVersion
from packages.sca.wheel_compat.wheel_tags import parse_wheel_filename


def test_pure_python_wheel_any_tag() -> None:
    tags = parse_wheel_filename("requests-2.31.0-py3-none-any.whl")
    assert len(tags) == 1
    assert tags[0].arch == "any"
    assert tags[0].libc is None
    assert tags[0].os == "any"


def test_manylinux_2_38_aarch64() -> None:
    """The canonical z3-solver case."""
    tags = parse_wheel_filename(
        "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"
    )
    assert len(tags) == 1
    assert tags[0].arch == "aarch64"
    assert tags[0].libc == LibcVersion("glibc", (2, 38))
    assert tags[0].os == "linux"


def test_manylinux_2_17_x86_64() -> None:
    tags = parse_wheel_filename(
        "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"
    )
    assert tags[0].arch == "x86_64"
    assert tags[0].libc == LibcVersion("glibc", (2, 17))


def test_manylinux2014_legacy_alias() -> None:
    """``manylinux2014_x86_64`` is the legacy alias for
    ``manylinux_2_17_x86_64``."""
    tags = parse_wheel_filename(
        "numpy-1.26.4-cp312-cp312-manylinux2014_x86_64.whl"
    )
    assert tags[0].libc == LibcVersion("glibc", (2, 17))
    assert tags[0].arch == "x86_64"


def test_manylinux1_legacy_alias() -> None:
    """``manylinux1`` → glibc 2.5."""
    tags = parse_wheel_filename(
        "oldpkg-1.0-py2-none-manylinux1_x86_64.whl"
    )
    assert tags[0].libc == LibcVersion("glibc", (2, 5))


def test_musllinux_1_2_aarch64() -> None:
    tags = parse_wheel_filename(
        "z3_solver-4.16.0.0-py3-none-musllinux_1_2_aarch64.whl"
    )
    assert tags[0].arch == "aarch64"
    assert tags[0].libc == LibcVersion("musl", (1, 2))
    assert tags[0].os == "linux"


def test_macosx_universal2() -> None:
    """macOS universal2 wheels carry two tags joined by ``.``."""
    tags = parse_wheel_filename(
        "cffi-1.16.0-cp312-cp312-macosx_11_0_arm64."
        "macosx_11_0_x86_64.whl"
    )
    assert len(tags) == 2
    arches = {t.arch for t in tags}
    assert arches == {"aarch64", "x86_64"}
    assert all(t.os == "macosx" for t in tags)


def test_win_amd64() -> None:
    tags = parse_wheel_filename(
        "numpy-1.26.4-cp312-cp312-win_amd64.whl"
    )
    assert tags[0].arch == "x86_64"
    assert tags[0].os == "windows"


def test_win32() -> None:
    tags = parse_wheel_filename(
        "numpy-1.26.4-cp312-cp312-win32.whl"
    )
    assert tags[0].arch == "i686"
    assert tags[0].os == "windows"


def test_unknown_platform_tag_passes_through() -> None:
    """An unrecognised tag yields a WheelTag with no constraints —
    we don't crash on shapes we haven't catalogued."""
    tags = parse_wheel_filename(
        "weird-1.0-py3-none-some_weird_tag.whl"
    )
    assert tags[0].arch is None
    assert tags[0].os == "unknown"


def test_non_wheel_filename_empty() -> None:
    assert parse_wheel_filename("requests-2.31.0.tar.gz") == []
    assert parse_wheel_filename("README.md") == []
    assert parse_wheel_filename("") == []


def test_build_tagged_wheel() -> None:
    """Wheels can carry a build tag between version and python-tag.
    Parser must still pull the platform-tag correctly."""
    tags = parse_wheel_filename(
        "foo-1.0-2-py3-none-manylinux_2_17_x86_64.whl"
    )
    assert tags[0].arch == "x86_64"
    assert tags[0].libc == LibcVersion("glibc", (2, 17))
