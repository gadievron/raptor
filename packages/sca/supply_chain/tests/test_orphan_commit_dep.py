"""Tests for ``packages.sca.supply_chain.orphan_commit_dep``.

Pinned against the Mini Shai-Hulud incident shape: an npm
package.json with a ``optionalDependencies`` block carrying a
``github:user/repo#SHA`` ref to an unrelated repository. The
detector should fire high-severity on that shape and lower-severity
on more-common git-ref patterns elsewhere in the file.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.supply_chain.orphan_commit_dep import scan_manifests


def _write(tmp_path: Path, payload: dict) -> Manifest:
    p = tmp_path / "package.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return Manifest(path=p, ecosystem="npm", is_lockfile=False)


def _dep(path: Path) -> Dependency:
    return Dependency(
        ecosystem="npm", name="size-sensor",
        version="1.0.0", declared_in=path,
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/size-sensor@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Negative cases (must not fire).
# ---------------------------------------------------------------------------

def test_no_dep_blocks_means_no_findings(tmp_path: Path) -> None:
    m = _write(tmp_path, {"name": "x", "version": "1.0.0"})
    assert scan_manifests([m], [_dep(m.path)]) == []


def test_plain_semver_deps_are_ignored(tmp_path: Path) -> None:
    """Normal semver-range deps are not git refs — must not fire."""
    m = _write(tmp_path, {"dependencies": {
        "lodash": "^4.17.21",
        "@scope/utility": "~2.0.0",
        "react": "18.2.0",
        "another": ">=1.0.0 <2.0.0",
    }})
    assert scan_manifests([m], [_dep(m.path)]) == []


def test_file_and_workspace_specs_are_ignored(tmp_path: Path) -> None:
    """``file:``, ``workspace:``, ``link:``, ``npm:`` aliases are
    not git refs — must not fire."""
    m = _write(tmp_path, {"dependencies": {
        "local-lib": "file:./packages/lib",
        "ws-lib": "workspace:*",
        "linked": "link:../other",
        "aliased": "npm:lodash@^4",
    }})
    assert scan_manifests([m], [_dep(m.path)]) == []


def test_http_tarball_ref_is_ignored(tmp_path: Path) -> None:
    """``https://`` tarball URLs are not git refs. (HTTP/S URLs to
    tarballs are uncommon but legitimate; not what this detector
    catches.)"""
    m = _write(tmp_path, {"dependencies": {
        "lib": "https://example.com/lib-1.0.tgz",
    }})
    assert scan_manifests([m], [_dep(m.path)]) == []


# ---------------------------------------------------------------------------
# Positive cases (must fire with the right severity).
# ---------------------------------------------------------------------------

def test_shai_hulud_shape_fires_high(tmp_path: Path) -> None:
    """The canonical Mini Shai-Hulud shape — ``optionalDependencies``
    pointing at a github ref pinned to a 40-char SHA in an unrelated
    repo. This is the row we cannot afford to miss."""
    m = _write(tmp_path, {
        "name": "size-sensor",
        "version": "2.5.1",
        "optionalDependencies": {
            "@antv/setup": (
                "github:antvis/G2#"
                "1916faa365f2788b6e193514872d51a242876569"
            ),
        },
    })
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.hit.field == "optionalDependencies"
    assert f.hit.owner == "antvis"
    assert f.hit.repo == "G2"
    assert f.hit.ref == "1916faa365f2788b6e193514872d51a242876569"
    assert f.hit.ref_kind == "sha40"
    assert "Shai-Hulud" in f.confidence.reason or (
        f.confidence.level == "high"
    )


def test_optional_deps_git_url_form_fires_high(tmp_path: Path) -> None:
    """Same shape but using the longer ``git+https://...#sha``
    form — still optionalDependencies, still high."""
    m = _write(tmp_path, {"optionalDependencies": {
        "lib": (
            "git+https://github.com/antvis/G2.git#"
            "1916faa365f2788b6e193514872d51a242876569"
        ),
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].hit.owner == "antvis"
    assert findings[0].hit.repo == "G2"


def test_optional_deps_tag_pinned_still_high(tmp_path: Path) -> None:
    """Even pinned to a tag — optionalDependencies + git ref is
    rare enough that we surface it. The shape is what's
    suspicious; the ref-kind only modulates severity for non-
    optional fields."""
    m = _write(tmp_path, {"optionalDependencies": {
        "lib": "github:antvis/G2#v1.0.0",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert findings[0].severity == "high"
    assert findings[0].hit.ref == "v1.0.0"
    assert findings[0].hit.ref_kind == "tag_or_branch"


def test_dependencies_sha_pinned_fires_medium(tmp_path: Path) -> None:
    """``dependencies`` with a SHA-pinned git ref is less suspicious
    than ``optionalDependencies`` (a SHA-pinned commit dep is at
    least reproducible) but still uncommon enough to surface."""
    m = _write(tmp_path, {"dependencies": {
        "lib": "github:org/repo#abcdef1234567890abcdef1234567890abcdef12",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].hit.ref_kind == "sha40"


def test_dependencies_tag_pinned_fires_low(tmp_path: Path) -> None:
    """Tag-pinned git ref in regular dependencies is the most-common
    legitimate use — fork + pin to a known release. Surface as low
    for SBOM awareness; not actionable on its own."""
    m = _write(tmp_path, {"dependencies": {
        "my-fork": "github:me/lib#v1.2.3",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].hit.ref_kind == "tag_or_branch"


def test_devdependencies_fires_too(tmp_path: Path) -> None:
    m = _write(tmp_path, {"devDependencies": {
        "test-helper": (
            "github:org/repo#abcdef1234567890abcdef1234567890abcdef12"
        ),
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].hit.field == "devDependencies"
    assert findings[0].severity == "medium"


def test_peerdependencies_fires_too(tmp_path: Path) -> None:
    """``peerDependencies`` rarely carries git refs, but for symmetry
    we scan it. Legitimate uses are vanishingly rare; surface at
    low (no auto-install) but don't ignore."""
    m = _write(tmp_path, {"peerDependencies": {
        "peer-lib": "github:org/repo#v1.0",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].hit.field == "peerDependencies"
    assert findings[0].severity == "low"


def test_multiple_refs_emit_multiple_findings(tmp_path: Path) -> None:
    """Two distinct git-refs in one package.json → two findings."""
    m = _write(tmp_path, {
        "optionalDependencies": {
            "a": "github:org1/r1#0000000000000000000000000000000000000000",
        },
        "dependencies": {
            "b": "github:org2/r2#1111111111111111111111111111111111111111",
        },
    })
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert severities == {"high", "medium"}


def test_bare_shorthand_with_ref_fires(tmp_path: Path) -> None:
    """``user/repo#ref`` (no ``github:`` prefix) is npm shorthand
    for the same shape. Require ``#ref`` to commit — bare ``a/b``
    without ref is often a workspace alias."""
    m = _write(tmp_path, {"dependencies": {
        "lib": "org/repo#abcdef1234567890abcdef1234567890abcdef12",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    assert findings[0].hit.owner == "org"
    assert findings[0].hit.repo == "repo"


def test_bare_shorthand_without_ref_does_not_fire(tmp_path: Path) -> None:
    """``a/b`` without ``#ref`` is ambiguous — could be workspace
    alias, monorepo path, etc. Don't auto-flag without the explicit
    ref segment."""
    m = _write(tmp_path, {"dependencies": {
        "lib": "org/repo",
    }})
    assert scan_manifests([m], [_dep(m.path)]) == []


def test_malformed_package_json_no_crash(tmp_path: Path) -> None:
    """Truncated / invalid JSON returns no findings, no exception."""
    p = tmp_path / "package.json"
    p.write_text("{not valid json", encoding="utf-8")
    m = Manifest(path=p, ecosystem="npm", is_lockfile=False)
    assert scan_manifests([m], [_dep(p)]) == []


def test_lockfile_path_is_skipped(tmp_path: Path) -> None:
    """We scan project ``package.json``, not lockfiles. Lockfiles
    don't carry the dep-shape we look for and would emit confusing
    duplicate rows."""
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"optionalDependencies": {
        "lib": "github:org/repo#abcdef1234567890abcdef1234567890abcdef12",
    }}), encoding="utf-8")
    m = Manifest(path=p, ecosystem="npm", is_lockfile=True)
    assert scan_manifests([m], [_dep(p)]) == []


def test_emits_through_supply_chain_orchestrator(tmp_path: Path) -> None:
    """End-to-end: the orchestrator's ``evaluate`` wires the new
    detector and surfaces a SupplyChainFinding with the documented
    shape (kind, evidence keys, severity)."""
    from packages.sca.supply_chain import evaluate
    m = _write(tmp_path, {"optionalDependencies": {
        "@antv/setup": (
            "github:antvis/G2#"
            "1916faa365f2788b6e193514872d51a242876569"
        ),
    }})
    findings = evaluate(
        target=tmp_path, manifests=[m], deps=[_dep(m.path)],
    )
    orphan_findings = [f for f in findings if f.kind == "orphan_commit_dep"]
    assert len(orphan_findings) == 1
    f = orphan_findings[0]
    assert f.severity == "high"
    assert f.evidence["field"] == "optionalDependencies"
    assert f.evidence["owner"] == "antvis"
    assert f.evidence["repo"] == "G2"
    assert f.evidence["ref_kind"] == "sha40"
    assert "Shai-Hulud" in f.detail
