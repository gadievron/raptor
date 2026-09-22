"""Tests for ``packages.sca.hygiene``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.hygiene import check_lockfile_missing, evaluate
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


def test_lockfile_missing_silenced_by_requirements_txt_sibling(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    reqs = tmp_path / "requirements.txt"
    pyproject.touch()
    reqs.touch()
    deps = [_dep("flask", ecosystem="PyPI", path=pyproject)]
    findings = evaluate(
        [_manifest(pyproject, "PyPI")],
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


def test_lockfile_missing_silenced_by_npm_shrinkwrap_sibling(
    tmp_path: Path,
) -> None:
    """npm's shrinkwrap lockfile is named ``npm-shrinkwrap.json`` — its
    physical presence beside package.json must satisfy the expectation."""
    pkg = tmp_path / "package.json"
    pkg.write_text("{}")
    (tmp_path / "npm-shrinkwrap.json").write_text("{}")
    findings = check_lockfile_missing(
        [_manifest(pkg, "npm")], [_dep("lodash", path=pkg)],
    )
    assert all(f.kind != "lockfile_missing" for f in findings)


def test_lockfile_missing_not_silenced_by_bare_shrinkwrap_name(
    tmp_path: Path,
) -> None:
    """A bare ``shrinkwrap.json`` is not an npm toolchain file and must
    NOT satisfy the lockfile expectation."""
    pkg = tmp_path / "package.json"
    pkg.write_text("{}")
    (tmp_path / "shrinkwrap.json").write_text("{}")
    findings = check_lockfile_missing(
        [_manifest(pkg, "npm")], [_dep("lodash", path=pkg)],
    )
    assert any(f.kind == "lockfile_missing" for f in findings)


# ---------------------------------------------------------------------------
# lockfile_missing silenced by -r include chain
# ---------------------------------------------------------------------------


def test_lockfile_missing_silenced_by_r_include_with_lockfile_sibling(
    tmp_path: Path,
) -> None:
    """A ``requirements-dev.txt`` with ``-r ../common/requirements.txt``
    should not fire lockfile_missing when ``common/`` has a lockfile
    sibling."""
    dev_dir = tmp_path / "app"
    dev_dir.mkdir()
    dev_reqs = dev_dir / "requirements-dev.txt"
    dev_reqs.write_text("-r ../common/requirements.txt\npytest==8.0\n")

    common_dir = tmp_path / "common"
    common_dir.mkdir()
    (common_dir / "requirements.txt").write_text("flask==3.0\n")
    (common_dir / "requirements.lock").write_text("flask==3.0.0\n")

    deps = [_dep("pytest", ecosystem="PyPI", path=dev_reqs)]
    findings = check_lockfile_missing(
        [_manifest(dev_reqs, "PyPI")],
        deps,
    )
    assert all(f.kind != "lockfile_missing" for f in findings), (
        "-r include target's sibling lockfile should suppress"
    )


def test_lockfile_missing_still_fires_when_r_include_target_has_no_lockfile(
    tmp_path: Path,
) -> None:
    """The -r include chain should NOT suppress when the included
    directory ALSO lacks a lockfile.  We use ``base.txt`` (not
    ``requirements.txt``) as the include target so the target's own
    filename doesn't accidentally satisfy the physical-file check
    (``requirements.txt`` IS one of the expected lockfile names)."""
    dev_dir = tmp_path / "app"
    dev_dir.mkdir()
    dev_reqs = dev_dir / "requirements-dev.txt"
    dev_reqs.write_text("-r ../common/base.txt\npytest==8.0\n")

    common_dir = tmp_path / "common"
    common_dir.mkdir()
    (common_dir / "base.txt").write_text("flask==3.0\n")
    # No lockfile in common/.

    deps = [_dep("pytest", ecosystem="PyPI", path=dev_reqs)]
    findings = check_lockfile_missing(
        [_manifest(dev_reqs, "PyPI")],
        deps,
    )
    assert any(f.kind == "lockfile_missing" for f in findings)


def test_r_include_with_traversal_is_skipped(tmp_path) -> None:
    """A hostile ``-r ../../...`` include must not steer the lockfile
    probe outside the scanned target (the old guard's two branches
    were byte-identical — a no-op). Containment, not a ``..`` ban:
    monorepo includes inside the root keep working."""
    from packages.sca.hygiene import _included_dir_has_lockfile

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.lock").write_text("x==1\n", encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    manifest = proj / "requirements.txt"
    manifest.write_text("-r ../outside/requirements.txt\n",
                        encoding="utf-8")
    (outside / "requirements.txt").write_text("x==1\n", encoding="utf-8")

    assert _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=proj,
    ) is False

    # Direction two: a legitimate same-tree include still counts.
    sub = proj / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("y==1\n", encoding="utf-8")
    (sub / "requirements.lock").write_text("y==1\n", encoding="utf-8")
    manifest.write_text("-r sub/requirements.txt\n", encoding="utf-8")
    assert _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=proj,
    ) is True
    # Monorepo direction: a ``..`` include that stays INSIDE the
    # scanned root keeps counting (containment, not a ``..`` ban).
    common = tmp_path / "common"
    common.mkdir()
    (common / "requirements.txt").write_text("z==1\n", encoding="utf-8")
    (common / "requirements.lock").write_text("z==1\n", encoding="utf-8")
    manifest.write_text("-r ../common/requirements.txt\n",
                        encoding="utf-8")
    assert _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=tmp_path,
    ) is True


def test_r_include_blank_line_run_is_fast(tmp_path) -> None:
    """Hostile requirements.txt carrying a blank-line RUN the greedy
    span cannot hand to a match: under the MULTILINE ``^`` anchor a
    ``\\s*`` indent matched at every line start inside the run and
    re-scanned the remainder per anchor — quadratic. The firing shape
    is an include with NO lockfile sibling (a resolved include
    short-circuits before the run is scanned). Horizontal-only indent
    is linear. Both-direction bound: the miss is fast AND a real
    include still resolves."""
    import time

    proj = tmp_path / "proj"
    proj.mkdir()
    bare = proj / "bare"
    bare.mkdir()
    (bare / "requirements.txt").write_text("z==1\n", encoding="utf-8")
    manifest = proj / "requirements.txt"
    manifest.write_text("-r bare/requirements.txt\nx==1\n"
                        + "\n" * (1 << 17) + "# end\n",
                        encoding="utf-8")

    from packages.sca.hygiene import _included_dir_has_lockfile

    start = time.monotonic()
    hit = _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=proj,
    )
    assert time.monotonic() - start < 5.0
    assert hit is False

    # Both-direction: a real include with a lockfile sibling still
    # resolves through the same hostile tail.
    sub = proj / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("y==1\n", encoding="utf-8")
    (sub / "requirements.lock").write_text("y==1\n", encoding="utf-8")
    manifest.write_text("-r sub/requirements.txt\nx==1\n"
                        + "\n" * (1 << 17) + "# end\n",
                        encoding="utf-8")
    start = time.monotonic()
    hit = _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=proj,
    )
    assert time.monotonic() - start < 5.0
    assert hit is True


def test_r_include_argument_must_share_the_line(tmp_path) -> None:
    """``-r`` with its argument on the NEXT line is not a pip include;
    the old cross-line ``\\s+`` silently captured it."""
    proj = tmp_path / "proj"
    proj.mkdir()
    sub = proj / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("y==1\n", encoding="utf-8")
    (sub / "requirements.lock").write_text("y==1\n", encoding="utf-8")
    manifest = proj / "requirements.txt"
    manifest.write_text("-r\nsub/requirements.txt\n", encoding="utf-8")

    from packages.sca.hygiene import _included_dir_has_lockfile

    assert _included_dir_has_lockfile(
        manifest, ("requirements.lock",), set(), "PyPI", root=proj,
    ) is False
