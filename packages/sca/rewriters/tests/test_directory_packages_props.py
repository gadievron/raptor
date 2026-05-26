"""Tests for the ``Directory.Packages.props`` rewriter."""

from __future__ import annotations

from pathlib import Path

from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.directory_packages_props import (
    rewrite_directory_packages_props,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "Directory.Packages.props"
    p.write_text(body, encoding="utf-8")
    return p


def test_rewrites_attribute_version(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageVersion Include="Other" Version="2.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="Newtonsoft.Json",
        old_value="13.0.1", new_value="13.0.3",
    )])
    assert results[0].applied is True
    body = p.read_text()
    assert 'Include="Newtonsoft.Json" Version="13.0.3"' in body
    # Untouched entry preserved verbatim.
    assert 'Include="Other" Version="2.0.0"' in body


def test_rewrites_global_package_reference(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <GlobalPackageReference Include="Microsoft.SourceLink.GitHub" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="Microsoft.SourceLink.GitHub",
        old_value="1.0.0", new_value="1.1.1",
    )])
    assert results[0].applied is True
    assert "1.1.1" in p.read_text()


def test_rewrites_child_element_version(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X">
      <Version>2.5.0</Version>
    </PackageVersion>
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="X", old_value="2.5.0", new_value="2.6.0",
    )])
    assert results[0].applied is True
    assert "<Version>2.6.0</Version>" in p.read_text()


def test_not_found_when_package_absent(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="A" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="Missing", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert results[0].reason == "not_found"


def test_value_mismatch_surfaces(tmp_path: Path):
    """Stale plan: the file's version has drifted from what the
    plan expected. Reject the write so we don't corrupt a file
    the operator already edited."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="A" Version="3.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="A", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert "value_mismatch" in results[0].reason
    # File untouched.
    assert "3.0.0" in p.read_text()


def test_dispatch_via_registry(tmp_path: Path):
    """Filename ``Directory.Packages.props`` is registered with
    the global rewrite dispatcher — operators / bumper hit this
    path automatically."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup><PackageVersion Include="A" Version="1.0.0" /></ItemGroup>
</Project>
""")
    results = rewrite(p, [RewriteEdit(
        locator="A", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True


def test_multiple_edits_in_one_pass(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="A" Version="1.0.0" />
    <PackageVersion Include="B" Version="2.0.0" />
    <PackageVersion Include="C" Version="3.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [
        RewriteEdit(locator="A", old_value="1.0.0", new_value="1.1.0"),
        RewriteEdit(locator="C", old_value="3.0.0", new_value="3.1.0"),
    ])
    assert all(r.applied for r in results)
    body = p.read_text()
    assert "1.1.0" in body
    assert "3.1.0" in body
    # B untouched.
    assert 'Include="B" Version="2.0.0"' in body


def test_idempotent_second_pass(tmp_path: Path):
    """Re-running an already-applied edit triggers value_mismatch
    (the file already has the new version, so old_value doesn't
    match). This is the documented idempotency contract."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup><PackageVersion Include="A" Version="2.0.0" /></ItemGroup>
</Project>
""")
    edit = RewriteEdit(
        locator="A", old_value="1.0.0", new_value="2.0.0",
    )
    results = rewrite_directory_packages_props(p, [edit])
    assert results[0].applied is False
    assert "value_mismatch" in results[0].reason
