"""Tests for the CycloneDX SBOM import path.

Two layers:
  * Unit — ``parse_cyclonedx`` against various CycloneDX shapes.
  * E2E — ``raptor-sca <target> --sbom <file> --offline`` skips
    manifest discovery and scans the SBOM's deps directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from packages.sca.sbom_import import parse_cyclonedx

REPO_ROOT = Path(__file__).resolve().parents[3]


def _write_cyclonedx(path: Path, components: list, **extras) -> Path:
    """Build a minimal CycloneDX 1.5 JSON with the given
    components list."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    sbom.update(extras)
    path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Unit: parse_cyclonedx
# ---------------------------------------------------------------------------

def test_parse_pypi_component(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
    ])
    deps, warnings = parse_cyclonedx(sbom)
    assert warnings == []
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "PyPI"
    assert d.name == "requests"
    assert d.version == "2.31.0"
    assert d.is_lockfile is True  # SBOM = resolved snapshot
    assert d.source_kind == "sbom_import"


def test_parse_maven_component_recomposes_groupid(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library",
            "name": "jackson-databind",
            "version": "2.16.0",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.0",
        },
    ])
    deps, warnings = parse_cyclonedx(sbom)
    assert warnings == []
    assert deps[0].ecosystem == "Maven"
    # SCA canonical Maven name: "groupId:artifactId"
    assert deps[0].name == "com.fasterxml.jackson.core:jackson-databind"
    assert deps[0].version == "2.16.0"


def test_parse_npm_scoped_package(tmp_path: Path) -> None:
    """``@scope/name`` in npm is URL-encoded in purls as
    ``%40scope/name``. Importer must decode the leading ``@``."""
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library",
            "name": "@types/node",
            "version": "20.10.0",
            "purl": "pkg:npm/%40types/node@20.10.0",
        },
    ])
    deps, _ = parse_cyclonedx(sbom)
    assert deps[0].ecosystem == "npm"
    assert deps[0].name == "@types/node"
    assert deps[0].version == "20.10.0"


def test_parse_multiple_ecosystems(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "requests", "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
        {
            "type": "library", "name": "lodash", "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
        },
        {
            "type": "library", "name": "serde", "version": "1.0.193",
            "purl": "pkg:cargo/serde@1.0.193",
        },
        {
            "type": "library", "name": "github.com/spf13/cobra",
            "version": "v1.8.0",
            "purl": "pkg:golang/github.com/spf13/cobra@v1.8.0",
        },
    ])
    deps, warnings = parse_cyclonedx(sbom)
    assert warnings == []
    ecos = {d.ecosystem for d in deps}
    assert ecos == {"PyPI", "npm", "Cargo", "Go"}


def test_parse_skips_component_without_purl(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "requests", "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
        # No purl → not usable
        {
            "type": "library", "name": "mystery", "version": "1.0",
        },
    ])
    deps, warnings = parse_cyclonedx(sbom)
    assert len(deps) == 1
    assert len(warnings) == 1
    assert "no usable purl" in warnings[0].lower()


def test_parse_skips_unsupported_purl_type(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {"type": "library", "name": "rare-thing", "version": "1.0",
         "purl": "pkg:hex/some-erlang/rare-thing@1.0"},   # erlang/hex
    ])
    deps, warnings = parse_cyclonedx(sbom)
    # Unsupported ecosystem → skipped with warning.
    assert deps == []
    assert len(warnings) == 1


def test_parse_extracts_license_spdx_id(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "requests", "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
    ])
    deps, _ = parse_cyclonedx(sbom)
    assert deps[0].declared_license == "Apache-2.0"


def test_parse_extracts_license_expression(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "requests", "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"expression": "Apache-2.0 OR MIT"}],
        },
    ])
    deps, _ = parse_cyclonedx(sbom)
    assert deps[0].declared_license == "Apache-2.0 OR MIT"


def test_parse_empty_sbom(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [])
    deps, warnings = parse_cyclonedx(sbom)
    assert deps == []


def test_parse_rejects_spdx_format(tmp_path: Path) -> None:
    """SPDX SBOMs have a different schema and we don't support
    them yet. Surface a clear error rather than a silent miss."""
    sbom_path = tmp_path / "spdx.json"
    sbom_path.write_text(json.dumps({
        "spdxVersion": "SPDX-2.3",
        "name": "fixture",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="not CycloneDX"):
        parse_cyclonedx(sbom_path)


def test_parse_rejects_invalid_json(tmp_path: Path) -> None:
    sbom_path = tmp_path / "broken.json"
    sbom_path.write_text("{not json{", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_cyclonedx(sbom_path)


def test_parse_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        parse_cyclonedx(tmp_path / "does-not-exist.json")


def test_parse_handles_scope_optional(tmp_path: Path) -> None:
    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "dev-tool", "version": "1.0",
            "purl": "pkg:pypi/dev-tool@1.0",
            "scope": "optional",
        },
    ])
    deps, _ = parse_cyclonedx(sbom)
    assert deps[0].scope == "optional"


# ---------------------------------------------------------------------------
# E2E: --sbom flag drives the pipeline
# ---------------------------------------------------------------------------


def test_e2e_scan_with_sbom_input(tmp_path: Path) -> None:
    """``raptor-sca <target> --sbom <file> --offline`` scans the
    SBOM's deps and skips manifest discovery."""
    # Empty target — proves the scan came from the SBOM, not from
    # discovering manifests in the target.
    empty = tmp_path / "empty"
    empty.mkdir()

    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "requests", "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
        {
            "type": "library", "name": "lodash", "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
        },
    ])

    out = tmp_path / "out"
    cmd = [
        sys.executable, "-m", "packages.sca.cli",
        str(empty), "--sbom", str(sbom),
        "--offline", "--out", str(out),
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=60,
    )
    assert proc.returncode in (0, 1), (
        f"scan with --sbom failed: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )
    # SBOM emit path runs as usual on the imported deps
    out_sbom = out / "sbom.cdx.json"
    assert out_sbom.is_file()
    out_data = json.loads(out_sbom.read_text())
    components = {c["name"] for c in out_data.get("components", [])}
    # Both deps from the input SBOM should appear in the output SBOM.
    assert "requests" in components
    assert "lodash" in components


def test_e2e_sbom_overrides_target_discovery(tmp_path: Path) -> None:
    """When ``--sbom`` is set, manifest discovery is SKIPPED —
    even if the target has manifests, they don't contribute."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Plant a manifest in the target that should be IGNORED.
    (repo / "requirements.txt").write_text(
        "should-not-appear==1.0\n", encoding="utf-8",
    )

    sbom = _write_cyclonedx(tmp_path / "sbom.json", [
        {
            "type": "library", "name": "from-sbom", "version": "2.0",
            "purl": "pkg:pypi/from-sbom@2.0",
        },
    ])

    out = tmp_path / "out"
    cmd = [
        sys.executable, "-m", "packages.sca.cli",
        str(repo), "--sbom", str(sbom),
        "--offline", "--out", str(out),
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=60,
    )
    assert proc.returncode in (0, 1)
    out_sbom = json.loads((out / "sbom.cdx.json").read_text())
    components = {c["name"] for c in out_sbom.get("components", [])}
    assert "from-sbom" in components, (
        f"SBOM-imported dep missing from output; got {components}"
    )
    assert "should-not-appear" not in components, (
        f"manifest discovery ran despite --sbom; got {components}"
    )
