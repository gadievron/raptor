"""Tests for the Directory.Build.targets <PackageReference Update=...>
rewriter — the pre-CPM central-version pattern."""

from __future__ import annotations

from pathlib import Path

from packages.sca.rewriters import RewriteEdit
from packages.sca.rewriters.directory_build_targets import (
    rewrite_directory_build_targets,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "Directory.Build.targets"
    p.write_text(body, encoding="utf-8")
    return p


def test_rewrites_inline_version_attribute(tmp_path: Path):
    """The central-version table form: <PackageReference Update="X"
    Version="Y"/>. This is the dominant pre-CPM shape."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Update="IdentityServer4" Version="3.1.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="IdentityServer4",
        old_value="3.1.0", new_value="4.1.2",
    )])
    assert results[0].applied is True
    assert 'Version="4.1.2"' in p.read_text()


def test_case_insensitive_locator(tmp_path: Path):
    """NuGet package names are case-insensitive — the locator should match
    regardless of casing in the file."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Update="NEWTONSOFT.JSON" Version="13.0.1" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="Newtonsoft.Json",
        old_value="13.0.1", new_value="13.0.3",
    )])
    assert results[0].applied is True


def test_value_mismatch_does_not_rewrite(tmp_path: Path):
    """If the file's current version differs from the edit's old_value,
    refuse rather than blind-overwrite (prevents stomping on out-of-date
    plans)."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Update="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""")
    body_before = p.read_text()
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="3.0.0",
    )])
    assert results[0].applied is False
    assert "value_mismatch" in (results[0].reason or "")
    assert p.read_text() == body_before


def test_unknown_package_is_not_found(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Update="Foo" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="Bar", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert (results[0].reason or "") == "not_found"


def test_include_attribute_is_not_matched(tmp_path: Path):
    """Update= and Include= are SEMANTICALLY different (override vs add).
    This rewriter must match Update= only — an Include= reference is the
    csproj rewriter's job."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    body_before = p.read_text()
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert p.read_text() == body_before


def test_child_version_element_shape(tmp_path: Path):
    """Older child-element shape: <PackageReference Update="X">
    <Version>OLD</Version></PackageReference>."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Update="X">
      <Version>1.0.0</Version>
    </PackageReference>
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_build_targets(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True
    assert "<Version>2.0.0</Version>" in p.read_text()
