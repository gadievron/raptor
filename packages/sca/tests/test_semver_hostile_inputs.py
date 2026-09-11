"""Semver parsing under hostile numeric components.

``int()`` over an unbounded digit run is quadratic CPU and, on
interpreters with an int-digit limit, raises ``ValueError`` from deep
inside ``bounds()`` — which has callers (package.json parsing) with
no try/except, so one hostile spec used to take the WHOLE manifest's
deps down. Digit runs are now length-bounded: an over-long run is a
parse failure contained to that single version/dep.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from packages.sca.parsers import package_json
from packages.sca.versions import VersionError, compare
from packages.sca.versions.semver import bounds, parse

_HUGE_DIGITS = "9" * 9000


def test_bounds_does_not_raise_on_huge_digit_run() -> None:
    """A hostile digit run yields "no bound", never an exception."""
    assert bounds(">=" + _HUGE_DIGITS) == (None, None)
    assert bounds(f"^{_HUGE_DIGITS}.0.0") == (None, None)
    assert bounds(f"1.0.0 - {_HUGE_DIGITS}.0.0") == ("1.0.0", None)


def test_parse_failure_is_versionerror_at_the_dispatcher() -> None:
    """A huge component is an unparseable version for that one
    comparison — the normal contained failure mode."""
    with pytest.raises(VersionError):
        compare("npm", f"1.{_HUGE_DIGITS}.0", "1.0.0")


def test_huge_numeric_prerelease_identifiers_compare() -> None:
    """Numeric pre-release identifiers are compared without int():
    arbitrarily long digit identifiers stay O(n) and raise nothing."""
    a = "1.0.0-" + "8" * 9000
    b = "1.0.0-" + "9" * 9000
    assert compare("npm", a, b) == -1
    assert compare("npm", b, a) == 1
    assert compare("npm", a, a) == 0


def test_normal_versions_unchanged() -> None:
    assert bounds("^1.2.3") == ("1.2.3", "2.0.0")
    assert bounds("~1.2.3") == ("1.2.3", "1.3.0")
    assert parse("v1.2.3-alpha.1") == (1, 2, 3, ["alpha", "1"])
    assert compare("npm", "1.0.0-alpha.2", "1.0.0-alpha.10") == -1
    assert compare("npm", "1.9.0", "1.10.0") == -1
    assert compare("Go", "v0.0.0-20210320205559-abc123",
                   "v0.0.0-20210321000000-def456") == -1


def test_one_hostile_spec_degrades_one_dep_not_the_manifest(
    tmp_path: Path,
) -> None:
    """package.json parsing survives a hostile range spec: the poisoned
    dep records no corridor, every other dep still comes through."""
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({
        "name": "fixture",
        "dependencies": {
            "poisoned": ">=" + _HUGE_DIGITS,
            "healthy": "^1.2.3",
            "pinned": "2.0.0",
        },
    }), encoding="utf-8")

    deps = package_json.parse(manifest)

    by_name = {d.name: d for d in deps}
    assert set(by_name) >= {"poisoned", "healthy", "pinned"}
    assert by_name["healthy"].version_floor == "1.2.3"
    assert by_name["healthy"].version_ceiling == "2.0.0"
    assert by_name["poisoned"].version_floor is None
    assert by_name["poisoned"].version_ceiling is None


def test_pathological_shapes_parse_in_linear_time() -> None:
    """CPU guard: hostile shapes must stay well under interactive
    latency (generous bound to keep slow CI runners green)."""
    shapes = [
        ">=" + "9" * 200_000,
        "1." + "9" * 200_000 + ".0",
        "1.2.3-" + "a." * 50_000 + "b",
        "py" + "3.10.0-6" * 20_000,
    ]
    start = time.perf_counter()
    for shape in shapes:
        bounds(shape)
        try:
            parse(shape)
        except ValueError:
            pass
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"pathological parse took {elapsed:.2f}s"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
