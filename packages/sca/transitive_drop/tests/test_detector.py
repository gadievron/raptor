"""Tests for the transitive-drop detector.

The canonical case driving this code: instructor 1.14.5 pins
diskcache>=5.6.3 unconditionally; instructor 1.15.1 moves it
behind ``extra == "diskcache"``. The detector spots the
state-change and recommends bumping instructor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from packages.sca.models import (
    Confidence, Dependency, PinStyle, VulnFinding,
)
from packages.sca.transitive_drop import detect_droppable_transitives


# ---------------------------------------------------------------------------
# Test stubs
# ---------------------------------------------------------------------------

class _StubPyPI:
    """Stub PyPI client with per-version requires_dist support."""

    def __init__(self, versions: Dict[str, Dict[str, Dict[str, Any]]]):
        # versions: {pkg: {version: {"requires_dist": [...], ...}}}
        self._v = versions

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        canon = name.lower().replace("_", "-")
        if canon not in self._v:
            return None
        releases = {ver: [] for ver in self._v[canon]}
        latest = max(
            self._v[canon].keys(),
            key=lambda v: tuple(int(x) if x.isdigit() else 0
                                 for x in v.split(".")),
        )
        info = dict(self._v[canon][latest])
        info["version"] = latest
        return {"info": info, "releases": releases}

    def get_version_metadata(
        self, name: str, version: str,
    ) -> Optional[Dict[str, Any]]:
        canon = name.lower().replace("_", "-")
        v = self._v.get(canon, {}).get(version)
        if v is None:
            return None
        info = dict(v)
        info["version"] = version
        return {"info": info}

    def list_versions(self, name: str) -> List[str]:
        canon = name.lower().replace("_", "-")
        return list(self._v.get(canon, {}).keys())


def _dep(name: str, version: str, *,
         direct: bool = True,
         source_kind: str = "manifest",
         via: Optional[List[str]] = None) -> Dependency:
    extra = {"via": via} if via else None
    return Dependency(
        ecosystem="PyPI", name=name, version=version,
        declared_in=Path(f"/test/{name}"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence("high", reason="test"),
        source_kind=source_kind,
        source_extra=extra,
    )


def _vuln(dep: Dependency, severity: str = "medium") -> VulnFinding:
    return VulnFinding(
        finding_id=f"sca:vuln:test:{dep.name}",
        dependency=dep,
        advisories=[],
        severity=severity,
        in_kev=False,
        epss=None,
        fixed_version=None,
        reachability=None,
        cvss_score=None,
        cvss_vector=None,
        version_match_confidence=Confidence("high", reason="test"),
        exposure_factor=1.0,
        transitive_depth=1,
    )


# ---------------------------------------------------------------------------
# The canonical case: instructor 1.14.5 → 1.15.1 drops diskcache
# ---------------------------------------------------------------------------

def test_diskcache_optional_in_newer_instructor() -> None:
    """Reproduces raptor's actual scan: ``requirements.txt`` pins
    ``instructor==1.14.5``; cascade resolver pulls in
    ``diskcache==5.6.3``; diskcache has CVE-2025-69872; the
    detector should suggest bumping instructor to 1.15.1 to drop
    the dep."""
    pypi = _StubPyPI({
        "instructor": {
            "1.14.5": {
                "requires_dist": [
                    "openai<3.0.0,>=2.0.0",
                    "diskcache>=5.6.3",   # UNCONDITIONAL
                    "rich<15.0.0,>=13.7.0",
                ],
            },
            "1.15.1": {
                "requires_dist": [
                    "openai<3.0.0,>=2.0.0",
                    'diskcache<6.0.0,>=5.6.3; extra == "diskcache"',  # behind extra
                    "rich<15.0.0,>=13.7.0",
                ],
            },
        },
        "diskcache": {"5.6.3": {}},
    })
    deps = [
        _dep("instructor", "1.14.5", direct=True),
        _dep("diskcache", "5.6.3",
             direct=False, source_kind="cascade_resolver",
             via=["instructor"]),
    ]
    vuln = _vuln(deps[1], severity="medium")
    findings = detect_droppable_transitives(
        deps, vuln_findings=[vuln], pypi_client=pypi,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.transitive_name == "diskcache"
    assert f.parent_name == "instructor"
    assert f.parent_current_version == "1.14.5"
    assert f.parent_latest_version == "1.15.1"
    assert f.transitive_status_in_latest == "extras-gated"
    assert f.extra_name == "diskcache"
    assert f.transitive_finding_severity == "medium"


def test_transitive_removed_entirely_in_newer_parent() -> None:
    """Some parent bumps remove the transitive dep entirely (not
    even behind an extra). Should still emit a finding, with
    status='removed'."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {
                "requires_dist": ["badpkg>=1.0"],
            },
            "2.0.0": {
                "requires_dist": [],   # no longer mentions badpkg
            },
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("badpkg", "1.5.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert len(findings) == 1
    assert findings[0].transitive_status_in_latest == "removed"
    assert findings[0].extra_name is None


def test_no_finding_when_already_at_latest() -> None:
    """If the parent is already at the latest version, no bump
    available → no finding (even if the dep is troublesome)."""
    pypi = _StubPyPI({
        "instructor": {
            "1.15.1": {
                "requires_dist": [
                    'diskcache; extra == "diskcache"',
                ],
            },
        },
    })
    deps = [
        _dep("instructor", "1.15.1", direct=True),
        _dep("diskcache", "5.6.3",
             direct=False, source_kind="cascade_resolver",
             via=["instructor"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert findings == []


def test_no_finding_when_transitive_still_required_in_latest() -> None:
    """If the dep is unconditional in BOTH current and latest, no
    suggestion is useful — the bump doesn't help."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ["dep>=1"]},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], pypi_client=pypi,
    )
    assert findings == []


def test_skips_transitives_without_findings() -> None:
    """If the transitive has no associated finding (vuln /
    supply-chain / hygiene), don't spend the PyPI roundtrip —
    the bump suggestion is only useful when there's a problem
    to solve."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ['dep; extra == "dep"']},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[], pypi_client=pypi,
    )
    # No vuln_findings → no transitive flagged → no work.
    assert findings == []


def test_severity_propagates_from_underlying_vuln() -> None:
    """High-severity vulns on droppable transitives are 'real
    fix' suggestions; their severity carries over."""
    pypi = _StubPyPI({
        "parent": {
            "1.0.0": {"requires_dist": ["dep>=1"]},
            "2.0.0": {"requires_dist": ['dep; extra == "extra"']},
        },
    })
    deps = [
        _dep("parent", "1.0.0", direct=True),
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps,
        vuln_findings=[_vuln(deps[1], severity="critical")],
        pypi_client=pypi,
    )
    assert findings[0].transitive_finding_severity == "critical"


def test_no_pypi_client_skips() -> None:
    deps = [
        _dep("dep", "1.0.0",
             direct=False, source_kind="cascade_resolver",
             via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[0])], pypi_client=None,
    )
    assert findings == []


def test_skips_non_pypi_transitives() -> None:
    """The detector is PyPI-specific (other ecosystems have
    different metadata shapes for optional deps)."""
    d = Dependency(
        ecosystem="npm", name="lodash", version="4.17.20",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:npm/lodash@4.17.20",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["express"]},
    )
    pypi = _StubPyPI({})
    findings = detect_droppable_transitives(
        [d], vuln_findings=[_vuln(d)], pypi_client=pypi,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

class _StubNpm:
    """Stub npm client returning packument-shaped data."""
    def __init__(self, packages):
        self._p = packages

    def get_metadata(self, name):
        return self._p.get(name)


def _npm_dep(name, version, *, direct=True, via=None):
    extra = {"via": via} if via else None
    return Dependency(
        ecosystem="npm", name=name, version=version,
        declared_in=Path(f"/test/{name}"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="manifest" if direct else "cascade_resolver",
        source_extra=extra,
    )


def test_npm_dependency_moved_to_optional() -> None:
    """parent@1.0.0 has ``dep`` in ``dependencies``;
    parent@2.0.0 moves it to ``optionalDependencies``.
    Bumping drops the implicit install."""
    npm = _StubNpm({
        "parent": {
            "versions": {
                "1.0.0": {
                    "dependencies": {"dep": "^1.0"},
                },
                "2.0.0": {
                    "optionalDependencies": {"dep": "^2.0"},
                },
            },
        },
    })
    deps = [
        _npm_dep("parent", "1.0.0", direct=True),
        _npm_dep("dep", "1.2.0", direct=False, via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], npm_client=npm,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.parent_name == "parent"
    assert f.parent_latest_version == "2.0.0"
    assert f.transitive_status_in_latest == "extras-gated"
    assert f.extra_name == "optionalDependencies"


def test_npm_dependency_moved_to_peer() -> None:
    npm = _StubNpm({
        "parent": {
            "versions": {
                "1.0.0": {"dependencies": {"dep": "^1.0"}},
                "2.0.0": {"peerDependencies": {"dep": "^2.0"}},
            },
        },
    })
    deps = [
        _npm_dep("parent", "1.0.0"),
        _npm_dep("dep", "1.0.0", direct=False, via=["parent"]),
    ]
    findings = detect_droppable_transitives(
        deps, vuln_findings=[_vuln(deps[1])], npm_client=npm,
    )
    assert len(findings) == 1
    assert findings[0].extra_name == "peerDependencies"


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

class _StubCargo:
    def __init__(self, deps_by_pair):
        self._d = deps_by_pair  # {(crate, version): [deps...]}
        self._latest = {}
        for (crate, ver), _ in deps_by_pair.items():
            cur = self._latest.get(crate)
            if cur is None or _version_lt(cur, ver):
                self._latest[crate] = ver

    def get_metadata(self, name):
        if name not in self._latest:
            return None
        # crates.io aggregate: ``{crate: {newest_version}, versions: [...]}``
        return {
            "releases": {
                v: [] for (c, v) in self._d.keys() if c == name
            },
            "info": {"version": self._latest[name]},
        }

    def get_version_dependencies(self, name, version):
        return self._d.get((name, version))


def _version_lt(a, b):
    pa = tuple(int(x) for x in a.split(".") if x.isdigit())
    pb = tuple(int(x) for x in b.split(".") if x.isdigit())
    return pa < pb


def test_cargo_dep_moves_to_optional() -> None:
    """parent@1.0.0 lists ``dep`` as ``kind=normal optional=false``;
    parent@2.0.0 makes it ``optional=true`` (feature-gated)."""
    cargo = _StubCargo({
        ("parent", "1.0.0"): [
            {"name": "dep", "kind": "normal", "optional": False},
        ],
        ("parent", "2.0.0"): [
            {"name": "dep", "kind": "normal", "optional": True},
        ],
    })
    # Synthesize Cargo Dependency rows.
    parent = Dependency(
        ecosystem="Cargo", name="parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:cargo/parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        ecosystem="Cargo", name="dep", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:cargo/dep@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        cargo_client=cargo,
    )
    assert len(findings) == 1
    assert findings[0].transitive_status_in_latest == "extras-gated"
    assert findings[0].extra_name == "optional-feature"


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

class _StubRubyGems:
    def __init__(self, deps_per_version):
        self._d = deps_per_version  # {(gem, version): {runtime: [], development: []}}

    def get_metadata(self, name):
        # Return latest version info
        vers = [v for (g, v) in self._d.keys() if g == name]
        if not vers:
            return None
        return {"releases": {v: [] for v in vers},
                "info": {"version": sorted(vers, reverse=True)[0]}}

    def get_version_metadata(self, name, version):
        if (name, version) not in self._d:
            return None
        return {
            "info": {"version": version},
            "dependencies": self._d[(name, version)],
        }


def test_rubygems_dep_moves_to_development() -> None:
    rg = _StubRubyGems({
        ("parent", "1.0.0"): {
            "runtime": [{"name": "dep", "requirements": ">= 1.0"}],
            "development": [],
        },
        ("parent", "2.0.0"): {
            "runtime": [],
            "development": [{"name": "dep", "requirements": ">= 2.0"}],
        },
    })
    parent = Dependency(
        ecosystem="RubyGems", name="parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:gem/parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        ecosystem="RubyGems", name="dep", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:gem/dep@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        rubygems_client=rg,
    )
    assert len(findings) == 1
    assert findings[0].transitive_status_in_latest == "extras-gated"
    assert findings[0].extra_name == "development"


# ---------------------------------------------------------------------------
# Composer (Packagist)
# ---------------------------------------------------------------------------

class _StubComposer:
    def __init__(self, pkgs):
        self._p = pkgs

    def get_metadata(self, name):
        if name not in self._p:
            return None
        # Packagist /p2 shape: {packages: {<name>: [{version, require, ...}]}}
        versions = self._p[name]
        return {
            "packages": {name: versions},
            "releases": {v["version"]: [] for v in versions},
            "info": {"version": sorted(
                (v["version"] for v in versions),
                key=_version_key, reverse=True,
            )[0]},
        }


def _version_key(v: str):
    return tuple(int(p) if p.isdigit() else 0 for p in v.split("."))


def test_composer_dep_match_is_case_folded() -> None:
    """Regression for the 2026-05-21 lint-sweep find:
    ``_dep_state_composer`` defined ``transitive_canon =
    transitive_name.lower()`` but used the raw mixed-case
    ``transitive_name`` for the dict lookups against
    ``require`` / ``require-dev`` / ``suggest``. A composer.json
    with a mixed-case entry (``vendor/Package``) would silently
    miss every check despite the canonical key being declared
    just above.

    Packagist enforces lowercase canonical names but hand-edited
    ``composer.json`` blocks routinely carry mixed case;
    matching case-folded is what every other ecosystem detector
    in the same module does (npm / Cargo / NuGet / RubyGems).
    Fix routes both sides of the comparison through
    ``.lower()``."""
    composer = _StubComposer({
        # Parent declares the dep with a MIXED-CASE key, but our
        # transitive lookup uses the lowercase canonical. The
        # `_has` helper inside `_dep_state_composer` must
        # case-fold both sides to find this match.
        "vendor/parent": [
            {"version": "1.0.0",
             "require": {"vendor/MixedCase": "^1.0"}},
            {"version": "2.0.0",
             "require-dev": {"vendor/MixedCase": "^2.0"}},
        ],
    })
    parent = Dependency(
        ecosystem="Packagist", name="vendor/parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:composer/vendor/parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        # OUR canonical name uses lowercase — the standard form
        # for transitive resolution. The detector must reconcile.
        ecosystem="Packagist", name="vendor/mixedcase", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:composer/vendor/mixedcase@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["vendor/parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        composer_client=composer,
    )
    # Pre-fix: zero findings (case mismatch missed both lookups).
    # Post-fix: the require-dev relocation is detected.
    assert len(findings) == 1, (
        f"case-folded composer match missed; got {findings!r}"
    )
    assert findings[0].extra_name == "require-dev"


def test_composer_dep_moves_to_require_dev() -> None:
    composer = _StubComposer({
        "vendor/parent": [
            {"version": "1.0.0", "require": {"vendor/dep": "^1.0"}},
            {"version": "2.0.0", "require-dev": {"vendor/dep": "^2.0"}},
        ],
    })
    parent = Dependency(
        ecosystem="Packagist", name="vendor/parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:composer/vendor/parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        ecosystem="Packagist", name="vendor/dep", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:composer/vendor/dep@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["vendor/parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        composer_client=composer,
    )
    assert len(findings) == 1
    assert findings[0].extra_name == "require-dev"


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

class _StubMaven:
    def __init__(self, poms):
        self._p = poms  # {(coord, version): {dependencies: [{groupId, artifactId, scope, optional}]}}
        self._latest = {}
        for (coord, ver), _ in poms.items():
            cur = self._latest.get(coord)
            if cur is None or _version_lt(cur, ver):
                self._latest[coord] = ver

    def get_metadata(self, name):
        if name not in self._latest:
            return None
        return {
            "releases": {
                v: [] for (c, v) in self._p.keys() if c == name
            },
            "info": {"version": self._latest[name]},
        }

    def get_pom(self, coord, version):
        return self._p.get((coord, version))


def test_maven_dep_scope_moves_to_test() -> None:
    mvn = _StubMaven({
        ("com.example:parent", "1.0.0"): {
            "dependencies": [
                {"groupId": "com.example", "artifactId": "dep",
                 "scope": "compile", "optional": "false"},
            ],
        },
        ("com.example:parent", "2.0.0"): {
            "dependencies": [
                {"groupId": "com.example", "artifactId": "dep",
                 "scope": "test", "optional": "false"},
            ],
        },
    })
    parent = Dependency(
        ecosystem="Maven", name="com.example:parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:maven/com.example/parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        ecosystem="Maven", name="com.example:dep", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:maven/com.example/dep@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["com.example:parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        maven_client=mvn,
    )
    assert len(findings) == 1
    assert findings[0].extra_name == "test"


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

class _StubNuGet:
    """NuGet is case-INsensitive in practice; stub mirrors that."""
    def __init__(self, nuspecs):
        # Normalise keys to lowercase to match canonical_name.
        self._n = {(p.lower(), v): nspec
                    for (p, v), nspec in nuspecs.items()}
        self._latest = {}
        for (pkg, ver) in self._n.keys():
            cur = self._latest.get(pkg)
            if cur is None or _version_lt(cur, ver):
                self._latest[pkg] = ver

    def get_metadata(self, name):
        n = name.lower()
        if n not in self._latest:
            return None
        return {
            "releases": {
                v: [] for (p, v) in self._n.keys() if p == n
            },
            "info": {"version": self._latest[n]},
        }

    def get_nuspec(self, pkg, version):
        return self._n.get((pkg.lower(), version))


def test_nuget_dep_disappears_from_all_tfms() -> None:
    ng = _StubNuGet({
        ("Parent", "1.0.0"): {
            "dependency_groups": [
                {"targetFramework": "net6.0",
                 "dependencies": [{"id": "Dep", "version": "1.0"}]},
            ],
        },
        ("Parent", "2.0.0"): {
            "dependency_groups": [
                {"targetFramework": "net6.0",
                 "dependencies": []},
            ],
        },
    })
    parent = Dependency(
        ecosystem="NuGet", name="Parent", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:nuget/Parent@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )
    transitive = Dependency(
        ecosystem="NuGet", name="Dep", version="1.0.0",
        declared_in=Path("/test"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:nuget/Dep@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="cascade_resolver",
        source_extra={"via": ["Parent"]},
    )
    findings = detect_droppable_transitives(
        [parent, transitive],
        vuln_findings=[_vuln(transitive)],
        nuget_client=ng,
    )
    assert len(findings) == 1
    assert findings[0].transitive_status_in_latest == "removed"
