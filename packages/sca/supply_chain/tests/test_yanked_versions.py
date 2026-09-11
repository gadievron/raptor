"""Tests for ``packages.sca.supply_chain.yanked_versions``.

Fake registry clients only — no network. The PyPI path in particular
must not pay a second round-trip (aggregate packument) for a dep
whose versioned response was well-formed and not yanked.
"""

from __future__ import annotations

import threading
from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.yanked_versions import scan_pinned_versions


def _dep(name: str, version: str = "1.0.0",
         ecosystem: str = "PyPI",
         pin_style: PinStyle = PinStyle.EXACT) -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("/p/requirements.txt"), scope="main",
        is_lockfile=False, pin_style=pin_style, direct=True,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


class _FakePyPI:
    """Counts calls per endpoint so tests can assert the aggregate
    fallback is / isn't consulted."""

    def __init__(self, version_meta: object = None,
                 aggregate_meta: object = None) -> None:
        self.version_meta = version_meta
        self.aggregate_meta = aggregate_meta
        self.version_calls = 0
        self.aggregate_calls = 0
        self._lock = threading.Lock()

    def get_version_metadata(self, name: str, version: str) -> object:
        with self._lock:
            self.version_calls += 1
        return self.version_meta

    def get_metadata(self, name: str) -> object:
        with self._lock:
            self.aggregate_calls += 1
        return self.aggregate_meta


def test_pypi_yanked_version_fires() -> None:
    client = _FakePyPI(version_meta={
        "info": {"yanked": True, "yanked_reason": "broken sdist"},
    })
    out = scan_pinned_versions([_dep("flask")], pypi_client=client)
    assert len(out) == 1
    assert out[0].kind == "yanked_version"
    assert "broken sdist" in out[0].detail


def test_pypi_clean_version_skips_aggregate_fallback() -> None:
    """A well-formed, not-yanked versioned response is authoritative
    — the aggregate packument must NOT be fetched as well (that
    doubled the round-trips for every clean dep)."""
    client = _FakePyPI(version_meta={"info": {"yanked": False}})
    out = scan_pinned_versions([_dep("flask")], pypi_client=client)
    assert out == []
    assert client.version_calls == 1
    assert client.aggregate_calls == 0


def test_pypi_malformed_version_response_still_falls_back() -> None:
    """Versioned endpoint returned junk (info missing) — the
    aggregate releases entry must still be consulted, and a yanked
    flag there still fires."""
    client = _FakePyPI(
        version_meta={"unexpected": "shape"},
        aggregate_meta={
            "releases": {"1.0.0": [{"yanked": True,
                                    "yanked_reason": "pulled"}]},
        },
    )
    out = scan_pinned_versions([_dep("flask")], pypi_client=client)
    assert len(out) == 1
    assert "pulled" in out[0].detail
    assert client.aggregate_calls == 1


def test_non_exact_pin_and_missing_version_skipped() -> None:
    client = _FakePyPI(version_meta={"info": {"yanked": True}})
    deps = [
        _dep("flask", pin_style=PinStyle.RANGE),
        Dependency(
            ecosystem="PyPI", name="jinja2", version=None,
            declared_in=Path("/p/requirements.txt"), scope="main",
            is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
            purl="pkg:pypi/jinja2",
            parser_confidence=Confidence("high", reason="t"),
        ),
    ]
    assert scan_pinned_versions(deps, pypi_client=client) == []
    assert client.version_calls == 0


def test_duplicate_deps_checked_once() -> None:
    client = _FakePyPI(version_meta={"info": {"yanked": False}})
    deps = [_dep("flask"), _dep("flask")]
    assert scan_pinned_versions(deps, pypi_client=client) == []
    assert client.version_calls == 1


def test_thread_pool_path_preserves_per_dep_results() -> None:
    """More than four unique deps takes the pooled path; every dep is
    checked exactly once and the yanked ones (and only those) come
    back, in input order."""

    class _SelectiveYank(_FakePyPI):
        def get_version_metadata(self, name: str, version: str) -> object:
            with self._lock:
                self.version_calls += 1
            return {"info": {"yanked": name.endswith("-bad"),
                             "yanked_reason": f"bye {name}"}}

    client = _SelectiveYank()
    names = ["a-ok", "b-bad", "c-ok", "d-bad", "e-ok", "f-bad"]
    out = scan_pinned_versions([_dep(n) for n in names],
                               pypi_client=client)
    assert client.version_calls == len(names)
    assert client.aggregate_calls == 0
    assert [f.dependency.name for f in out] == ["b-bad", "d-bad", "f-bad"]
