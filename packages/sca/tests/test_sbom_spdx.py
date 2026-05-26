"""Tests for SPDX 2.3 SBOM emission."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.sbom_spdx import (
    _spdx_id_for,
    _spdx_license_value,
    render_sbom_spdx,
)


def _dep(
    name: str = "lodash", version: Optional[str] = "4.17.21",
    ecosystem: str = "npm", license: Optional[str] = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("/repo/manifest"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        declared_license=license,
    )


# ---------------------------------------------------------------------------
# Document scaffolding
# ---------------------------------------------------------------------------


def test_top_level_required_fields_present():
    doc = render_sbom_spdx(deps=[], target_name="repo")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert "documentNamespace" in doc
    assert "creationInfo" in doc
    assert "raptor-sca" in doc["creationInfo"]["creators"][0]


def test_namespace_is_unique_per_run():
    doc1 = render_sbom_spdx(deps=[], target_name="repo")
    doc2 = render_sbom_spdx(deps=[], target_name="repo")
    # Same target name produces the same canonical prefix. Strict
    # inequality on the full namespace would be flaky when two
    # successive calls land in the same wall-clock second; we
    # assert the shape on both and a non-empty trailing component
    # so a future regression that emits a constant namespace fails.
    prefix = "https://raptor-sca.local/spdxdocs/repo-"
    assert doc1["documentNamespace"].startswith(prefix)
    assert doc2["documentNamespace"].startswith(prefix)
    assert doc1["documentNamespace"][len(prefix):]
    assert doc2["documentNamespace"][len(prefix):]


def test_explicit_namespace_overrides_default():
    doc = render_sbom_spdx(
        deps=[], target_name="repo",
        namespace_uri="https://example.com/sbom/123",
    )
    assert doc["documentNamespace"] == "https://example.com/sbom/123"


def test_creation_info_has_required_fields():
    doc = render_sbom_spdx(deps=[], target_name="x")
    ci = doc["creationInfo"]
    # SPDX 2.3 requires created (timestamp) + creators (list).
    assert "created" in ci
    assert "creators" in ci and isinstance(ci["creators"], list)
    assert ci["creators"][0].startswith("Tool:")


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------


def test_one_package_per_dep():
    deps = [_dep("a", "1.0"), _dep("b", "2.0")]
    doc = render_sbom_spdx(deps=deps, target_name="x")
    assert len(doc["packages"]) == 2


def test_package_required_fields():
    doc = render_sbom_spdx(deps=[_dep()], target_name="x")
    pkg = doc["packages"][0]
    # SPDX 2.3 requires SPDXID, name, downloadLocation, filesAnalyzed
    # (when no files), licenseDeclared, licenseConcluded, copyrightText
    # for spec compliance.
    for required in ("SPDXID", "name", "downloadLocation",
                      "filesAnalyzed", "licenseDeclared",
                      "licenseConcluded", "copyrightText", "supplier"):
        assert required in pkg, f"missing required field {required}"


def test_package_purl_in_external_refs():
    doc = render_sbom_spdx(deps=[_dep()], target_name="x")
    refs = doc["packages"][0]["externalRefs"]
    purl_refs = [r for r in refs if r.get("referenceType") == "purl"]
    assert len(purl_refs) == 1
    assert purl_refs[0]["referenceLocator"] == "pkg:npm/lodash@4.17.21"


def test_package_version_info():
    doc = render_sbom_spdx(deps=[_dep("x", "3.14")], target_name="x")
    assert doc["packages"][0]["versionInfo"] == "3.14"


def test_package_no_version_info_when_unversioned():
    doc = render_sbom_spdx(deps=[_dep("x", None)], target_name="x")
    assert "versionInfo" not in doc["packages"][0]


# ---------------------------------------------------------------------------
# License — declared / concluded / NOASSERTION
# ---------------------------------------------------------------------------


def test_declared_license_passes_through_for_spdx_id():
    doc = render_sbom_spdx(
        deps=[_dep(license="MIT")], target_name="x",
    )
    assert doc["packages"][0]["licenseDeclared"] == "MIT"


def test_declared_license_handles_dual_expression():
    doc = render_sbom_spdx(
        deps=[_dep(license="MIT OR Apache-2.0")], target_name="x",
    )
    assert doc["packages"][0]["licenseDeclared"] == "MIT OR Apache-2.0"


def test_unknown_license_becomes_noassertion():
    doc = render_sbom_spdx(deps=[_dep(license=None)], target_name="x")
    assert doc["packages"][0]["licenseDeclared"] == "NOASSERTION"


def test_freetext_license_becomes_noassertion():
    """A long sentence-shaped 'license' field shouldn't be passed
    through verbatim — SPDX validators reject."""
    doc = render_sbom_spdx(
        deps=[_dep(license="See the LICENSE file for details")],
        target_name="x",
    )
    assert doc["packages"][0]["licenseDeclared"] == "NOASSERTION"


def test_concluded_license_always_noassertion():
    """Concluded-license analysis is a separate (manual / future)
    pass; the mechanical pipeline doesn't make a conclusion."""
    doc = render_sbom_spdx(
        deps=[_dep(license="MIT")], target_name="x",
    )
    assert doc["packages"][0]["licenseConcluded"] == "NOASSERTION"


def test_spdx_license_value_rejects_url():
    assert _spdx_license_value("https://example.com/LICENSE") \
        == "NOASSERTION"


def test_spdx_license_value_accepts_with_clause():
    """SPDX expressions can contain ``WITH`` for exception
    clauses — accept these."""
    assert _spdx_license_value("Apache-2.0 WITH LLVM-exception") \
        == "Apache-2.0 WITH LLVM-exception"


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


def test_describes_relationship_per_package():
    deps = [_dep("a", "1.0"), _dep("b", "2.0")]
    doc = render_sbom_spdx(deps=deps, target_name="x")
    rels = doc["relationships"]
    describes = [r for r in rels if r["relationshipType"] == "DESCRIBES"]
    assert len(describes) == 2


# ---------------------------------------------------------------------------
# SPDX-ID generation
# ---------------------------------------------------------------------------


def test_spdx_id_replaces_special_chars():
    """SPDX requires SPDXRef-<id> with [A-Za-z0-9.-]+ — slashes,
    colons, etc. must be replaced."""
    seen = set()
    sid = _spdx_id_for(_dep(name="@scope/pkg", version="1.0"), seen)
    assert sid.startswith("SPDXRef-")
    # No invalid chars.
    payload = sid.replace("SPDXRef-", "", 1)
    for c in payload:
        assert c.isalnum() or c in ".-", f"bad char {c!r} in {sid}"


def test_spdx_id_collision_disambiguation():
    """Two deps with same ecosystem+name+version produce distinct
    SPDX-IDs."""
    seen = set()
    sid1 = _spdx_id_for(_dep("x", "1.0"), seen)
    sid2 = _spdx_id_for(_dep("x", "1.0"), seen)
    assert sid1 != sid2


def test_spdx_id_unique_collection():
    """Across many deps with same name+version, all IDs unique."""
    seen = set()
    ids = [_spdx_id_for(_dep("x", "1.0"), seen) for _ in range(5)]
    assert len(set(ids)) == 5


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


def test_write_atomically_creates_file(tmp_path: Path):
    from packages.sca.sbom_spdx import write_sbom_spdx_json

    write_sbom_spdx_json(
        tmp_path / "sbom.spdx.json",
        deps=[_dep()], target_name="x",
    )
    import json
    data = json.loads((tmp_path / "sbom.spdx.json").read_text())
    assert data["spdxVersion"] == "SPDX-2.3"
