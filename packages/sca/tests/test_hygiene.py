"""Tests for ``packages.sca.hygiene``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.hygiene import evaluate
from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)


def _dep(
    name: str,
    *,
    version: str | None = "1.0.0",
    ecosystem: str = "npm",
    pin_style: PinStyle = PinStyle.EXACT,
    is_lockfile: bool = False,
    path: Path,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=path,
        scope="main",
        is_lockfile=is_lockfile,
        pin_style=pin_style,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(path: Path, ecosystem: str, is_lockfile: bool = False) -> Manifest:
    return Manifest(path=path, ecosystem=ecosystem, is_lockfile=is_lockfile)


# ---------------------------------------------------------------------------
# lockfile_missing
# ---------------------------------------------------------------------------

def test_lockfile_missing_for_npm_manifest_alone(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.touch()
    deps = [_dep("lodash", path=pkg)]
    findings = evaluate(
        [_manifest(pkg, "npm")],
        deps,
    )
    kinds = [f.kind for f in findings]
    assert "lockfile_missing" in kinds


def test_lockfile_missing_silenced_when_lockfile_sibling_exists(
    tmp_path: Path,
) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    pkg.touch()
    lock.touch()
    deps = [_dep("lodash", path=pkg),
            _dep("lodash", path=lock, is_lockfile=True)]
    findings = evaluate(
        [_manifest(pkg, "npm"), _manifest(lock, "npm", is_lockfile=True)],
        deps,
    )
    assert all(f.kind != "lockfile_missing" for f in findings)


def test_lockfile_missing_skipped_for_ecosystems_without_expectation(
    tmp_path: Path,
) -> None:
    pom = tmp_path / "pom.xml"
    pom.touch()
    findings = evaluate(
        [_manifest(pom, "Maven")],
        [_dep("g:a", ecosystem="Maven", path=pom)],
    )
    assert all(f.kind != "lockfile_missing" for f in findings)


# ---------------------------------------------------------------------------
# lockfile_drift
# ---------------------------------------------------------------------------

def test_lockfile_drift_when_exact_pin_disagrees_with_lockfile(
    tmp_path: Path,
) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _dep("lodash", version="4.17.21", path=pkg, pin_style=PinStyle.EXACT),
        _dep("lodash", version="4.17.20", path=lock, is_lockfile=True),
    ]
    findings = evaluate([], deps)
    drift = [f for f in findings if f.kind == "lockfile_drift"]
    assert len(drift) == 1
    assert "4.17.21" in drift[0].detail
    assert "4.17.20" in drift[0].detail


def test_lockfile_drift_silenced_when_versions_match(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _dep("lodash", version="4.17.21", path=pkg),
        _dep("lodash", version="4.17.21", path=lock, is_lockfile=True),
    ]
    findings = evaluate([], deps)
    assert all(f.kind != "lockfile_drift" for f in findings)


def test_lockfile_drift_skipped_for_loose_pin(tmp_path: Path) -> None:
    """A caret-pinned manifest *expecting* the lockfile to choose a
    higher version is not drift — it's the design."""
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _dep("lodash", version="4.17.0", path=pkg, pin_style=PinStyle.CARET),
        _dep("lodash", version="4.17.21", path=lock, is_lockfile=True),
    ]
    findings = evaluate([], deps)
    assert all(f.kind != "lockfile_drift" for f in findings)


# ---------------------------------------------------------------------------
# unpinned + loose
# ---------------------------------------------------------------------------

def test_unpinned_for_wildcard(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    deps = [_dep("lodash", version=None, path=pkg, pin_style=PinStyle.WILDCARD)]
    findings = evaluate([], deps)
    assert any(f.kind == "unpinned_dependency" for f in findings)


def test_maven_version_none_exempt_from_unpinned(tmp_path: Path) -> None:
    """Maven child poms intentionally omit ``<version>`` when the
    parent POM's ``<dependencyManagement>`` does the pinning.
    Pre-fix this detector flagged 1468 such entries at medium
    severity on a single Spring Boot project — a 100%-false-
    positive cascade. The exemption skips Maven ``version=None``
    so the genuine Maven unpin-via-parent idiom doesn't surface
    as hygiene noise."""
    pom = tmp_path / "pom.xml"
    deps = [_dep(
        "org.springframework.boot:spring-boot-actuator",
        version=None, path=pom, ecosystem="Maven",
        pin_style=PinStyle.UNKNOWN,
    )]
    findings = evaluate([], deps)
    assert not any(
        f.kind == "unpinned_dependency" for f in findings
    ), "Maven version=None must be exempt — parent POM is pinning it"


def test_npm_version_none_still_flagged(tmp_path: Path) -> None:
    """The Maven exemption is ecosystem-specific. npm / PyPI /
    etc. with version=None should still surface as unpinned."""
    pkg = tmp_path / "package.json"
    deps = [_dep("lodash", version=None, path=pkg, ecosystem="npm",
                  pin_style=PinStyle.UNKNOWN)]
    findings = evaluate([], deps)
    assert any(f.kind == "unpinned_dependency" for f in findings)


def test_loose_pin_for_caret(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    deps = [_dep("lodash", path=pkg, pin_style=PinStyle.CARET)]
    findings = evaluate([], deps)
    assert any(f.kind == "loose_pin" for f in findings)


def test_lockfile_rows_dont_trigger_pin_findings(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    deps = [_dep("lodash", path=lock, is_lockfile=True,
                 pin_style=PinStyle.WILDCARD, version=None)]
    findings = evaluate([], deps)
    # Lockfile rows aren't "the operator's pinning" — don't double-flag.
    assert all(f.kind not in ("unpinned_dependency", "loose_pin") for f in findings)


# ---------------------------------------------------------------------------
# cross_manifest_inconsistency
# ---------------------------------------------------------------------------

def test_cross_manifest_inconsistency_across_workspaces(tmp_path: Path) -> None:
    a = tmp_path / "a" / "package.json"
    b = tmp_path / "b" / "package.json"
    deps = [_dep("lodash", version="4.17.21", path=a),
            _dep("lodash", version="4.17.10", path=b)]
    findings = evaluate([], deps)
    assert any(f.kind == "cross_manifest_inconsistency" for f in findings)


def test_cross_manifest_inconsistency_silenced_within_workspace(
    tmp_path: Path,
) -> None:
    """Two manifests in the same dir disagreeing is unusual but not a
    cross-workspace problem; we don't flag it here."""
    p = tmp_path / "package.json"
    pyp = tmp_path / "pyproject.toml"   # pretend npm lives here too
    deps = [_dep("lodash", version="1.0", path=p),
            _dep("lodash", version="2.0", path=pyp)]
    findings = evaluate([], deps)
    assert all(f.kind != "cross_manifest_inconsistency" for f in findings)


def test_cross_manifest_inconsistency_silenced_when_versions_match(
    tmp_path: Path,
) -> None:
    a = tmp_path / "a" / "package.json"
    b = tmp_path / "b" / "package.json"
    deps = [_dep("lodash", version="1.0", path=a),
            _dep("lodash", version="1.0", path=b)]
    findings = evaluate([], deps)
    assert all(f.kind != "cross_manifest_inconsistency" for f in findings)


def test_cross_manifest_main_vs_optional_does_not_fire(tmp_path: Path) -> None:
    """``requirements.txt`` (main) and ``requirements-all-optional.txt``
    (optional extras) ARE expected to declare different versions —
    they serve different purposes. Without role-aware partitioning,
    every multi-extras project would surface bogus
    cross_manifest_inconsistency findings."""
    main = tmp_path / "requirements.txt"
    extras = tmp_path / ".devcontainer" / "requirements-all-optional.txt"
    deps = [_dep("anthropic", version="0.40.0", path=main),
            _dep("anthropic", version="0.100.0", path=extras)]
    findings = evaluate([], deps)
    assert all(f.kind != "cross_manifest_inconsistency" for f in findings), (
        "main vs optional manifest divergence is normal, not a finding"
    )


def test_cross_manifest_main_vs_dev_does_not_fire(tmp_path: Path) -> None:
    """``requirements.txt`` and ``requirements-dev.txt`` legitimately
    pin different versions of overlapping deps (dev tools may want
    a different pin than runtime). Different role → no comparison."""
    main = tmp_path / "requirements.txt"
    dev = tmp_path / "requirements-dev.txt"
    deps = [_dep("pytest", version="8.0.0", path=main),
            _dep("pytest", version="9.0.2", path=dev)]
    findings = evaluate([], deps)
    assert all(f.kind != "cross_manifest_inconsistency" for f in findings)


def test_cross_manifest_within_main_role_still_fires(tmp_path: Path) -> None:
    """Defends the inverse case — same-role mismatch IS a real
    finding. Two ``requirements.txt`` files in different workspaces
    declaring different versions is a workspace-divergence problem."""
    a = tmp_path / "a" / "requirements.txt"
    b = tmp_path / "b" / "requirements.txt"
    deps = [_dep("requests", version="2.31.0", path=a),
            _dep("requests", version="2.33.1", path=b)]
    findings = evaluate([], deps)
    assert any(f.kind == "cross_manifest_inconsistency" for f in findings)


def test_manifest_role_helper_handles_common_filenames():
    """Spot-check the filename classifier so future tweaks don't
    silently shift the dev/test/optional taxonomy."""
    from packages.sca.hygiene import _manifest_role
    assert _manifest_role(Path("requirements.txt")) == "main"
    assert _manifest_role(Path("pyproject.toml")) == "main"
    assert _manifest_role(Path("requirements-dev.txt")) == "dev"
    assert _manifest_role(Path("dev-requirements.txt")) == "dev"
    assert _manifest_role(Path("requirements-test.txt")) == "test"
    assert _manifest_role(Path("requirements-all-optional.txt")) == "optional"
    assert _manifest_role(Path("requirements-extras.txt")) == "optional"
    # Bare requirements-*.txt that's not main/dev/test → optional.
    assert _manifest_role(Path("requirements-prod.txt")) == "optional"
