"""Tests for ``packages.sca.supply_chain.git_drift``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.git_drift import scan_deps


def _git_dep(version: str, name: str = "fork-of-something",
             pin_style: PinStyle = PinStyle.GIT) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=version,
        declared_in=Path("/x/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Should flag
# ---------------------------------------------------------------------------

def test_branch_ref_flagged_medium() -> None:
    findings = scan_deps([_git_dep("main")])
    assert len(findings) == 1
    assert findings[0].ref_kind == "branch_or_other"
    assert findings[0].severity == "medium"


def test_master_branch_flagged() -> None:
    findings = scan_deps([_git_dep("master")])
    assert findings and findings[0].ref_kind == "branch_or_other"


def test_feature_branch_flagged() -> None:
    findings = scan_deps([_git_dep("feature/new-thing")])
    assert findings and findings[0].ref_kind == "branch_or_other"


def test_short_sha_treated_as_branch_or_other() -> None:
    """A 7-char abbreviated SHA isn't actually unique to a commit;
    git deduplicates collisions on the longer form. Treat it as
    ambiguous → branch_or_other (medium severity)."""
    findings = scan_deps([_git_dep("abc1234")])
    assert findings and findings[0].ref_kind == "branch_or_other"


def test_v_prefixed_tag_flagged_low() -> None:
    findings = scan_deps([_git_dep("v1.2.3")])
    assert len(findings) == 1
    assert findings[0].ref_kind == "tag"
    assert findings[0].severity == "low"


def test_bare_semver_tag_flagged_low() -> None:
    findings = scan_deps([_git_dep("4.17.21")])
    assert findings and findings[0].ref_kind == "tag"


def test_date_shaped_tag_flagged() -> None:
    findings = scan_deps([_git_dep("20250115")])
    assert findings and findings[0].ref_kind == "tag"


# ---------------------------------------------------------------------------
# Should NOT flag
# ---------------------------------------------------------------------------

def test_full_sha_not_flagged() -> None:
    sha = "b4ffde65f46336ab88eb53be808477a3936bae11"
    assert scan_deps([_git_dep(sha)]) == []


def test_uppercase_sha_not_flagged() -> None:
    sha = "B4FFDE65F46336AB88EB53BE808477A3936BAE11"
    assert scan_deps([_git_dep(sha)]) == []


def test_non_git_pin_styles_ignored() -> None:
    """Only ``pin_style=GIT`` deps are considered; everything else is
    out of scope for this detector."""
    findings = scan_deps([
        _git_dep("4.17.21", pin_style=PinStyle.EXACT),
        _git_dep("^4.17.0", pin_style=PinStyle.CARET),
        _git_dep("/local/path", pin_style=PinStyle.PATH),
    ])
    assert findings == []


def test_empty_version_skipped() -> None:
    """A git dep without a known ref shouldn't crash the detector."""
    deps = [Dependency(
        ecosystem="npm", name="x", version=None,
        declared_in=Path("/x/package.json"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.GIT, direct=True,
        purl="pkg:npm/x", parser_confidence=Confidence("high", reason="t"),
    )]
    assert scan_deps(deps) == []


# ---------------------------------------------------------------------------
# Go pseudo-versions — SHA-equivalent, must not be flagged
# ---------------------------------------------------------------------------

def test_go_pseudo_version_v0_no_base_tag_not_flagged() -> None:
    """``v0.0.0-yyyymmddhhmmss-{12hex}`` is Go's standard shape
    for a dep at an untagged commit. The 12-hex IS the commit SHA
    prefix; go.sum verifies the full hash. Treating these as
    branch-pinned (the pre-fix behaviour) produced 406 spurious
    medium-severity findings on Helm-3.5 alone — every Go module
    using untagged commits."""
    findings = scan_deps([
        _git_dep("v0.0.0-20160811212531-371fbbdaa898",
                  name="bazil.org/fuse"),
        _git_dep("v0.0.0-20191023171146-3cf2f69b5738",
                  name="go.etcd.io/etcd"),
        _git_dep("v0.0.0-20180830031419-95f893ade6f2",
                  name="github.com/phayes/freeport"),
    ])
    assert findings == []


def test_go_pseudo_version_with_release_base_tag_not_flagged() -> None:
    """``vX.Y.Z-0.yyyymmddhhmmss-{12hex}`` — release tag at base
    plus untagged commit afterward. Same immutability properties."""
    findings = scan_deps([
        _git_dep("v1.2.3-0.20240101120000-abcdef123456",
                  name="example.com/post-release"),
    ])
    assert findings == []


def test_go_pseudo_version_with_prerelease_base_tag_not_flagged() -> None:
    """``vX.Y.Z-pre.0.yyyymmddhhmmss-{12hex}`` — pre-release tag
    at base. Less common in the wild but the Go ref documents it."""
    findings = scan_deps([
        _git_dep("v2.0.0-pre.0.20240101120000-abcdef123456",
                  name="example.com/pre-release-base"),
    ])
    assert findings == []


def test_pseudo_versionish_but_invalid_still_flagged() -> None:
    """A close-but-not-quite shape (e.g. wrong SHA length) should
    still be flagged — we don't want the relaxation to over-match
    and silence genuine branch refs that happen to look pseudo."""
    findings = scan_deps([
        # Only 8 hex chars, not 12 — not a valid Go pseudo-version.
        _git_dep("v0.0.0-20240101120000-abcdef12",
                  name="ecosystem-not-go"),
    ])
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Multiple deps
# ---------------------------------------------------------------------------

def test_mixed_set_only_non_sha_git_deps_flagged() -> None:
    findings = scan_deps([
        _git_dep("main", name="branch-pinned"),
        _git_dep("v1.0.0", name="tag-pinned"),
        _git_dep("b4ffde65f46336ab88eb53be808477a3936bae11",
                 name="sha-pinned"),
        _git_dep("^2.0", pin_style=PinStyle.CARET, name="caret-pinned"),
    ])
    flagged = sorted(f.dependency.name for f in findings)
    assert flagged == ["branch-pinned", "tag-pinned"]
