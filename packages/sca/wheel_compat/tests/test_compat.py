"""Tests for the wheel-matrix builder + cross-check engine."""

from __future__ import annotations

from packages.sca.platform_matrix import PlatformPair, ProjectPlatformMatrix
from packages.sca.platform_matrix.glibc_db import LibcVersion
from packages.sca.wheel_compat.compat import (
    check_compat, wheel_matrix_for_version,
)


class _StubPyPI:
    """Returns the canned metadata dict for matching name lookups."""
    def __init__(self, packages: dict):
        self._p = packages

    def get_metadata(self, name: str):
        return self._p.get(name)


def _pair(arch: str, family: str, ver: tuple) -> PlatformPair:
    return PlatformPair(
        arch=arch, libc=LibcVersion(family, ver),
        source="test",
    )


# ---------------------------------------------------------------------------
# wheel_matrix_for_version
# ---------------------------------------------------------------------------

def test_wheel_matrix_for_version_extracts_tags() -> None:
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0.tar.gz"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    assert wm is not None
    assert wm.has_sdist is True
    assert len(wm.wheel_tags) == 2
    arches = sorted(t.arch for t in wm.wheel_tags)
    assert arches == ["aarch64", "x86_64"]


def test_wheel_matrix_unknown_version_none() -> None:
    pypi = _StubPyPI({"foo": {"releases": {"1.0": []}}})
    assert wheel_matrix_for_version(pypi, "foo", "9.9.9") is None


def test_wheel_matrix_pkg_not_on_pypi_none() -> None:
    pypi = _StubPyPI({})
    assert wheel_matrix_for_version(pypi, "ghost", "1.0") is None


# ---------------------------------------------------------------------------
# check_compat — the z3-solver canonical case
# ---------------------------------------------------------------------------

def test_z3_solver_aarch64_bookworm_libc_too_new() -> None:
    """The canonical bite: z3-solver==4.16.0.0 ships
    manylinux_2_38_aarch64 + manylinux_2_17_x86_64. A
    bookworm-based devcontainer (glibc 2.36) on aarch64 has no
    fit; x86_64 fits the 2_17 fallback."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 36)))
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    verdicts = check_compat(matrix, wm)
    by_arch = {v.pair.arch: v for v in verdicts}
    assert by_arch["x86_64"].verdict == "ok"
    assert by_arch["aarch64"].verdict == "libc_too_new"
    assert "glibc 2.38" in by_arch["aarch64"].reason
    assert "glibc 2.36" in by_arch["aarch64"].reason


def test_compat_ok_when_libc_satisfied() -> None:
    """A trixie-based devcontainer (glibc 2.39) satisfies
    manylinux_2_38 on aarch64."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 39)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "ok"


def test_compat_pure_python_ok_everywhere() -> None:
    """A pure-Python ``any`` wheel satisfies every platform pair."""
    pypi = _StubPyPI({
        "requests": {
            "releases": {
                "2.31.0": [
                    {"filename": "requests-2.31.0-py3-none-any.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "requests", "2.31.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 31)))
    matrix.add(_pair("aarch64", "glibc", (2, 28)))
    matrix.add(_pair("ppc64le", "glibc", (2, 17)))
    verdicts = check_compat(matrix, wm)
    assert all(v.verdict == "ok" for v in verdicts)


def test_compat_arch_gap() -> None:
    """Package ships only x86_64 wheels + no sdist; aarch64 has
    no installable option."""
    pypi = _StubPyPI({
        "amdonly": {
            "releases": {
                "1.0": [
                    {"filename":
                     "amdonly-1.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "amdonly", "1.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 31)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "arch_gap"


def test_compat_sdist_only_when_no_wheel_for_arch() -> None:
    """No matching wheel but sdist exists → sdist_only (needs
    build env in the install path)."""
    pypi = _StubPyPI({
        "amdonly": {
            "releases": {
                "1.0": [
                    {"filename":
                     "amdonly-1.0-py3-none-manylinux_2_17_x86_64.whl"},
                    {"filename": "amdonly-1.0.tar.gz"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "amdonly", "1.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 31)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "sdist_only"


def test_compat_uninstallable_no_wheels_no_sdist() -> None:
    pypi = _StubPyPI({
        "ghost": {"releases": {"1.0": []}},
    })
    wm = wheel_matrix_for_version(pypi, "ghost", "1.0")
    assert wm is None  # no version data → no compat answer


# ---------------------------------------------------------------------------
# find_compatible_version — recommendation engine
# ---------------------------------------------------------------------------

def test_find_compatible_version_walks_back_to_z3_pre_2_38() -> None:
    """The canonical z3-solver case: 4.16.0.0 needs glibc 2.38 on
    aarch64; an earlier version with manylinux_2_34 wheels would
    satisfy a glibc 2.36 base. The recommendation engine finds
    that earlier version."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                ],
                "4.15.8.0": [
                    {"filename":
                     "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                ],
                "4.15.0.0": [
                    {"filename":
                     "z3_solver-4.15.0.0-py3-none-manylinux_2_17_aarch64.whl"},
                ],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    rec = find_compatible_version(pypi, "z3-solver", matrix)
    # Highest-compatible: 4.15.8.0 (manylinux_2_34 fits glibc 2.36).
    assert rec == "4.15.8.0"


def test_find_compatible_version_none_when_no_match() -> None:
    """Every released version requires too-new libc → no
    recommendation."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "newpkg": {
            "releases": {
                "2.0.0": [{"filename":
                          "newpkg-2.0.0-py3-none-manylinux_2_38_aarch64.whl"}],
                "1.0.0": [{"filename":
                          "newpkg-1.0.0-py3-none-manylinux_2_39_aarch64.whl"}],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    assert find_compatible_version(pypi, "newpkg", matrix) is None


def test_find_compatible_version_skips_pre_releases() -> None:
    """Pre-release versions (``rc1``, ``b1``, ``.dev0``) are
    skipped — operators want stable recs."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "preview": {
            "releases": {
                "2.0.0rc1": [{"filename":
                              "preview-2.0.0rc1-py3-none-any.whl"}],
                "1.0.0": [{"filename":
                           "preview-1.0.0-py3-none-any.whl"}],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 36)))
    assert find_compatible_version(pypi, "preview", matrix) == "1.0.0"


# ---------------------------------------------------------------------------
# Per-version recommendation cache
# ---------------------------------------------------------------------------


class _CountingStubPyPI:
    """Stub that records how many times ``get_metadata`` is called.
    Lets us verify the recommendation cache eliminates redundant
    fetches when the same dep appears in multiple manifests."""

    def __init__(self, packages: dict):
        self._p = packages
        self.metadata_calls = 0

    def get_metadata(self, name: str):
        self.metadata_calls += 1
        return self._p.get(name)


def test_recommendation_cache_hits_avoid_pypi_refetch():
    """Two calls with the same (name, matrix-shape) only fetch
    PyPI metadata once."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )

    clear_recommendation_cache()
    pypi = _CountingStubPyPI({
        "z3-solver": {
            "releases": {
                "4.15.8.0": [
                    {"filename":
                     "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                ],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))

    assert find_compatible_version(pypi, "z3-solver", matrix) == "4.15.8.0"
    first_calls = pypi.metadata_calls
    assert first_calls >= 1  # at least the get_metadata call
    # Second call — identical inputs. No new PyPI fetch.
    assert find_compatible_version(pypi, "z3-solver", matrix) == "4.15.8.0"
    assert pypi.metadata_calls == first_calls, (
        "cache miss on second call with identical (name, matrix)"
    )


def test_recommendation_cache_ignores_pair_source_field():
    """``PlatformPair.source`` is operator-facing diagnostic text;
    two matrices that differ only in source must share a cache
    entry."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )

    clear_recommendation_cache()
    pypi = _CountingStubPyPI({
        "z3-solver": {
            "releases": {
                "4.15.8.0": [
                    {"filename":
                     "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                ],
            },
        },
    })
    matrix_a = ProjectPlatformMatrix()
    matrix_a.add(PlatformPair(
        arch="aarch64", libc=LibcVersion("glibc", (2, 36)),
        source="Dockerfile FROM python:3.13-bookworm",
    ))
    matrix_b = ProjectPlatformMatrix()
    matrix_b.add(PlatformPair(
        arch="aarch64", libc=LibcVersion("glibc", (2, 36)),
        source="GHA runs-on: ubuntu-22.04",
    ))

    assert find_compatible_version(pypi, "z3-solver", matrix_a) == "4.15.8.0"
    first_calls = pypi.metadata_calls
    assert find_compatible_version(pypi, "z3-solver", matrix_b) == "4.15.8.0"
    assert pypi.metadata_calls == first_calls, (
        "cache key incorrectly varies by PlatformPair.source"
    )


def test_recommendation_cache_distinguishes_different_matrices():
    """Two matrices with different (arch, libc) sets must NOT share
    a cache entry — they'd produce different recommendations."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )

    clear_recommendation_cache()
    pypi = _CountingStubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
                "4.15.8.0": [
                    {"filename":
                     "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                ],
            },
        },
    })

    matrix_aarch_2_36 = ProjectPlatformMatrix()
    matrix_aarch_2_36.add(_pair("aarch64", "glibc", (2, 36)))
    matrix_x86 = ProjectPlatformMatrix()
    matrix_x86.add(_pair("x86_64", "glibc", (2, 36)))

    # x86_64 / glibc 2.36: 4.16.0.0 fits (manylinux_2_17_x86_64 covers it)
    assert find_compatible_version(pypi, "z3-solver", matrix_x86) == "4.16.0.0"
    first_calls = pypi.metadata_calls

    # aarch64 / glibc 2.36: 4.16.0.0 doesn't fit; 4.15.8.0 does
    assert find_compatible_version(
        pypi, "z3-solver", matrix_aarch_2_36) == "4.15.8.0"
    assert pypi.metadata_calls > first_calls, (
        "cache incorrectly reused entry across different matrices"
    )


def test_recommendation_cache_caches_none_result():
    """When no version is compatible, the negative result is cached
    too — a second call shouldn't re-walk the exhausted history."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )

    clear_recommendation_cache()
    pypi = _CountingStubPyPI({
        "newpkg": {
            "releases": {
                "2.0.0": [{"filename":
                          "newpkg-2.0.0-py3-none-manylinux_2_38_aarch64.whl"}],
                "1.0.0": [{"filename":
                          "newpkg-1.0.0-py3-none-manylinux_2_39_aarch64.whl"}],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))

    assert find_compatible_version(pypi, "newpkg", matrix) is None
    first_calls = pypi.metadata_calls
    assert find_compatible_version(pypi, "newpkg", matrix) is None
    assert pypi.metadata_calls == first_calls, (
        "negative result not cached — second call re-walked history"
    )


def test_recommendation_cache_does_not_cache_failure():
    """A PyPI fetch exception is a transient signal — don't cache
    None and lock future calls into a broken result."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )

    clear_recommendation_cache()

    class _FailThenSucceed:
        def __init__(self):
            self.calls = 0
            self.payload = {
                "z3-solver": {
                    "releases": {
                        "4.15.8.0": [
                            {"filename":
                             "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                        ],
                    },
                },
            }

        def get_metadata(self, name):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("transient")
            return self.payload.get(name)

    pypi = _FailThenSucceed()
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))

    assert find_compatible_version(pypi, "z3-solver", matrix) is None
    # Second call retries (cache wasn't poisoned) and succeeds.
    assert find_compatible_version(pypi, "z3-solver", matrix) == "4.15.8.0"


# ---------------------------------------------------------------------------
# macOS version gating
# ---------------------------------------------------------------------------


def _macos_pair(arch: str, macos_version: tuple) -> PlatformPair:
    return PlatformPair(
        arch=arch, libc=None, source="test",
        macos_version=macos_version,
    )


def test_macos_wheel_too_new_for_project_runner():
    """Project on macos-12, dep ships ``macosx_14_0_arm64`` wheel
    only → verdict ``macos_too_new``. This is the silent miss the
    pre-fix code happily said OK to."""
    pypi = _StubPyPI({
        "shiny-c-ext": {
            "releases": {
                "1.0.0": [
                    {"filename":
                     "shiny_c_ext-1.0.0-cp311-cp311-macosx_14_0_arm64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "shiny-c-ext", "1.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_macos_pair("aarch64", (12, 0)))
    verdicts = check_compat(matrix, wm)
    assert len(verdicts) == 1
    assert verdicts[0].verdict == "macos_too_new", (
        f"expected macos_too_new, got {verdicts[0].verdict} "
        f"({verdicts[0].reason})"
    )
    assert "macosx_14_0_arm64" in verdicts[0].matching_wheel


def test_macos_wheel_matches_when_runner_is_newer():
    """Project on macos-14, dep wheel is ``macosx_11_0_arm64`` —
    newer macOS accepts older-tag wheels."""
    pypi = _StubPyPI({
        "shiny-c-ext": {
            "releases": {
                "1.0.0": [
                    {"filename":
                     "shiny_c_ext-1.0.0-cp311-cp311-macosx_11_0_arm64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "shiny-c-ext", "1.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_macos_pair("aarch64", (14, 0)))
    verdicts = check_compat(matrix, wm)
    assert len(verdicts) == 1
    assert verdicts[0].verdict == "ok"


def test_macos_no_version_pin_stays_lenient():
    """Project pair has macos_version=None (operator didn't pin a
    GHA macos-N runner) → fall through to "arch match decides"
    behaviour; even macosx_14 wheels match."""
    pypi = _StubPyPI({
        "shiny-c-ext": {
            "releases": {
                "1.0.0": [
                    {"filename":
                     "shiny_c_ext-1.0.0-cp311-cp311-macosx_14_0_arm64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "shiny-c-ext", "1.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(PlatformPair(arch="aarch64", libc=None, source="test"))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "ok", (
        "macos_version=None pair must stay lenient"
    )


def test_recommendation_cache_distinguishes_macos_versions():
    """A project on macos-12 should get a different recommendation
    than one on macos-14 — they accept different wheel-tag windows."""
    from packages.sca.wheel_compat.compat import (
        clear_recommendation_cache, find_compatible_version,
    )
    clear_recommendation_cache()
    pypi = _StubPyPI({
        "shiny-c-ext": {
            "releases": {
                "2.0.0": [
                    {"filename":
                     "shiny_c_ext-2.0.0-cp311-cp311-macosx_14_0_arm64.whl"},
                ],
                "1.5.0": [
                    {"filename":
                     "shiny_c_ext-1.5.0-cp311-cp311-macosx_11_0_arm64.whl"},
                ],
            },
        },
    })
    matrix_12 = ProjectPlatformMatrix()
    matrix_12.add(_macos_pair("aarch64", (12, 0)))
    matrix_14 = ProjectPlatformMatrix()
    matrix_14.add(_macos_pair("aarch64", (14, 0)))
    rec_12 = find_compatible_version(pypi, "shiny-c-ext", matrix_12)
    rec_14 = find_compatible_version(pypi, "shiny-c-ext", matrix_14)
    # macos-12 must walk back to 1.5.0 (the macosx_11 wheel); the
    # macos-14 user can stay on 2.0.0.
    assert rec_12 == "1.5.0", f"macos-12 should pick 1.5.0, got {rec_12}"
    assert rec_14 == "2.0.0", f"macos-14 should pick 2.0.0, got {rec_14}"
    # Critically: the two results MUST differ. Pre-cache-key-fix,
    # both shared an entry and would return the same value.
    assert rec_12 != rec_14, (
        "cache key collision — macos_version not in cache key"
    )


# ---------------------------------------------------------------------------
# musllinux UX touch-up
# ---------------------------------------------------------------------------


def test_musl_project_glibc_only_dep_gets_actionable_alpine_hint():
    """Project on Alpine (musl) + dep ships only manylinux (glibc)
    wheels → verdict ``sdist_only`` with actionable build-tools
    hint that mentions ``apk add build-base python3-dev``."""
    pypi = _StubPyPI({
        "compiled-thing": {
            "releases": {
                "1.0.0": [
                    {"filename":
                     "compiled_thing-1.0.0-cp311-cp311-manylinux_2_28_x86_64.whl"},
                    {"filename":
                     "compiled-thing-1.0.0.tar.gz"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "compiled-thing", "1.0.0")
    assert wm is not None and wm.has_sdist
    matrix = ProjectPlatformMatrix()
    # Alpine 3.19 musl
    matrix.add(PlatformPair(
        arch="x86_64",
        libc=LibcVersion("musl", (1, 2, 4)),
        source="test",
    ))
    verdicts = check_compat(matrix, wm)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.verdict == "sdist_only"
    # Actionable hints — both the apk command + the base-image
    # alternative should appear so the operator has a clear fix.
    assert "apk add build-base" in v.reason
    assert "python:3.X-bookworm" in v.reason
