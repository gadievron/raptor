"""Plan-only ``fix --cve-only`` must never write the source manifest.

The NuGet (csproj / Directory.Packages.props / Directory.Build.targets)
and Gradle version-catalog rewrites route through the ``rewriters/``
registry, whose functions atomic-write the path they're handed.
``_rewrite_via_registry`` therefore has to run the registry against a
scratch copy: a plan-only run (no ``--apply``) that mutates the
operator's tree is a policy violation, and it also breaks
``--git-patch`` (the "old" side of the diff is re-read from the source
manifest, which must still be pristine when the patch is emitted).
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca import update

from .test_update import _findings_file, _vuln_row


_CSPROJ_BODY = """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
  </ItemGroup>
</Project>
"""

_CATALOG_BODY = """\
[versions]
kotlin = "1.9.20"

[libraries]
commons-text = { module = "org.apache.commons:commons-text", version = "1.9" }
"""


def _run_plan_only(tmp_path: Path, findings: Path) -> Path:
    out = tmp_path / "out"
    rc = update.main([
        "--findings", str(findings), "--out", str(out),
        "--git-patch", "--offline",
    ])
    assert rc == 0
    return out


def test_plan_only_csproj_leaves_source_untouched(tmp_path: Path) -> None:
    csproj = tmp_path / "AppA.csproj"
    csproj.write_text(_CSPROJ_BODY, encoding="utf-8")
    before = csproj.read_bytes()
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="NuGet", name="Newtonsoft.Json",
        version="12.0.3", fixed_version="12.0.5",
        manifest=csproj,
    )])

    out = _run_plan_only(tmp_path, findings)

    # The change was applied to the PLAN, not the source tree.
    changes = json.loads((out / "changes.json").read_text())
    assert changes[0]["skipped_reason"] is None
    assert csproj.read_bytes() == before

    proposed = list((out / "proposed").rglob("AppA.csproj"))
    assert len(proposed) == 1
    assert 'Version="12.0.5"' in proposed[0].read_text()

    # --git-patch: the old side is the pristine original, so the
    # patch carries a real hunk (old version out, new version in).
    patch = (out / "upgrade.patch").read_text()
    assert '-    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />' in patch
    assert '+    <PackageReference Include="Newtonsoft.Json" Version="12.0.5" />' in patch


def test_plan_only_gradle_catalog_leaves_source_untouched(tmp_path: Path) -> None:
    catalog = tmp_path / "libs.versions.toml"
    catalog.write_text(_CATALOG_BODY, encoding="utf-8")
    before = catalog.read_bytes()
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="Maven", name="commons-text",
        version="1.9", fixed_version="1.10.0",
        manifest=catalog,
    )])

    out = _run_plan_only(tmp_path, findings)

    changes = json.loads((out / "changes.json").read_text())
    assert changes[0]["skipped_reason"] is None
    assert catalog.read_bytes() == before

    proposed = list((out / "proposed").rglob("libs.versions.toml"))
    assert len(proposed) == 1
    assert 'version = "1.10.0"' in proposed[0].read_text()

    patch = (out / "upgrade.patch").read_text()
    assert '-commons-text = { module = "org.apache.commons:commons-text", version = "1.9" }' in patch
    assert '+commons-text = { module = "org.apache.commons:commons-text", version = "1.10.0" }' in patch
