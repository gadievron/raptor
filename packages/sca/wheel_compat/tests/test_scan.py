"""Tests for the scan-time wheel-platform-compat hygiene check."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import (
    Confidence, Dependency, PinStyle,
)
from packages.sca.platform_matrix import (
    PlatformPair, ProjectPlatformMatrix,
)
from packages.sca.platform_matrix.glibc_db import LibcVersion
from packages.sca.wheel_compat.scan import evaluate_platform_compat


class _StubPyPI:
    def __init__(self, packages: dict):
        self._p = packages

    def get_metadata(self, name: str):
        return self._p.get(name)


def _dep(name: str, version: str, *, ecosystem: str = "PyPI") -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path(f"/test/{name}"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="test"),
    )


def _matrix_bookworm_dual_arch() -> ProjectPlatformMatrix:
    """The canonical raptor-self-scan situation: bookworm-based
    devcontainer on both x86_64 and aarch64."""
    m = ProjectPlatformMatrix()
    libc = LibcVersion("glibc", (2, 36))
    m.add(PlatformPair(arch="x86_64", libc=libc, source="test"))
    m.add(PlatformPair(arch="aarch64", libc=libc, source="test"))
    return m


def test_z3_solver_4_16_0_0_high_finding_with_recommendation(
    tmp_path: Path,
) -> None:
    """The canonical bite: z3-solver==4.16.0.0 ships
    manylinux_2_38_aarch64; bookworm has glibc 2.36; the finding
    surfaces HIGH severity AND recommends 4.15.x (the last
    version with compatible wheels)."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
                "4.15.0.0": [
                    {"filename":
                     "z3_solver-4.15.0.0-py3-none-manylinux_2_34_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.15.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    deps = [_dep("z3-solver", "4.16.0.0")]
    matrix = _matrix_bookworm_dual_arch()
    findings = evaluate_platform_compat(
        deps, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "platform_compat"
    assert f.severity == "high"
    assert "aarch64" in f.detail
    assert "glibc 2.38" in f.detail
    assert "Recommended: pin z3-solver==4.15.0.0" in f.detail


def test_pure_python_pin_no_finding(tmp_path: Path) -> None:
    """``any``-tagged wheels satisfy every platform pair."""
    pypi = _StubPyPI({
        "requests": {
            "releases": {
                "2.31.0": [
                    {"filename": "requests-2.31.0-py3-none-any.whl"},
                ],
            },
        },
    })
    deps = [_dep("requests", "2.31.0")]
    matrix = _matrix_bookworm_dual_arch()
    findings = evaluate_platform_compat(
        deps, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    assert findings == []


def test_dep_with_no_pypi_data_silently_skipped(tmp_path: Path) -> None:
    """A pin for a package PyPI doesn't return data for shouldn't
    crash the scan — return no finding."""
    pypi = _StubPyPI({})
    deps = [_dep("ghost-pkg", "1.0.0")]
    matrix = _matrix_bookworm_dual_arch()
    findings = evaluate_platform_compat(
        deps, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    assert findings == []


def test_non_pypi_ecosystem_ignored(tmp_path: Path) -> None:
    """npm / maven / etc. have no wheels; the detector is
    PyPI-only."""
    pypi = _StubPyPI({})
    deps = [_dep("lodash", "4.17.21", ecosystem="npm")]
    matrix = _matrix_bookworm_dual_arch()
    findings = evaluate_platform_compat(
        deps, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    assert findings == []


def test_no_pypi_client_silently_skipped(tmp_path: Path) -> None:
    """Without a PyPI client (offline / no-network runs), the
    detector is a no-op."""
    deps = [_dep("z3-solver", "4.16.0.0")]
    matrix = _matrix_bookworm_dual_arch()
    findings = evaluate_platform_compat(
        deps, target=tmp_path,
        pypi_client=None, platform_matrix=matrix,
    )
    assert findings == []


def test_dedups_same_pin_seen_twice(tmp_path: Path) -> None:
    """A pin declared in two files (requirements.txt + requirements-
    dev.txt) shouldn't double up findings — dedup is on
    (name, version) not on Dependency identity."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    # aarch64 wheel exists but needs glibc 2.38;
                    # x86_64 wheel covers glibc 2.17+ so OK.
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    deps_once = [_dep("z3-solver", "4.16.0.0")]
    deps_twice = [
        _dep("z3-solver", "4.16.0.0"),
        _dep("z3-solver", "4.16.0.0"),
    ]
    matrix = _matrix_bookworm_dual_arch()
    findings_once = evaluate_platform_compat(
        deps_once, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    findings_twice = evaluate_platform_compat(
        deps_twice, target=tmp_path,
        pypi_client=pypi, platform_matrix=matrix,
    )
    # Same pin seen twice → same set of findings (dedup on
    # (name, version) prevents the double-up).
    assert len(findings_once) == len(findings_twice)
    assert len(findings_once) == 1   # only aarch64 is problematic
