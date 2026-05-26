"""Tests for the .csproj / .fsproj / .vbproj PackageReference
rewriter."""

from __future__ import annotations

from pathlib import Path

from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.csproj import rewrite_csproj


def _write(tmp_path: Path, body: str, name: str = "App.csproj") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_rewrites_inline_version_attribute(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
""")
    results = rewrite_csproj(p, [RewriteEdit(
        locator="Newtonsoft.Json",
        old_value="13.0.1", new_value="13.0.3",
    )])
    assert results[0].applied is True
    assert 'Version="13.0.3"' in p.read_text()


def test_rewrites_version_override(tmp_path: Path):
    """CPM per-csproj override: ``VersionOverride="..."`` is the
    correct attribute to update when the dep's source-origin is
    ``version_override``. The csproj parser surfaces this via
    ``source_extra.origin``; the harden caller passes the
    csproj manifest path and this rewriter picks
    VersionOverride over an absent Version attribute."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" VersionOverride="9.9.9" />
  </ItemGroup>
</Project>
""")
    results = rewrite_csproj(p, [RewriteEdit(
        locator="X", old_value="9.9.9", new_value="9.10.0",
    )])
    assert results[0].applied is True
    assert 'VersionOverride="9.10.0"' in p.read_text()


def test_inline_version_wins_over_override(tmp_path: Path):
    """If BOTH attributes are present (rare; non-canonical MSBuild
    but technically legal), prefer updating ``Version`` since it's
    the more common form. ``VersionOverride`` is left alone — an
    operator who has both deserves a manual review anyway."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="1.0.0" VersionOverride="2.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_csproj(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="1.5.0",
    )])
    assert results[0].applied is True
    body = p.read_text()
    assert 'Version="1.5.0"' in body
    assert 'VersionOverride="2.0.0"' in body


def test_rewrites_child_element_version(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X">
      <Version>1.0.0</Version>
    </PackageReference>
  </ItemGroup>
</Project>
""")
    results = rewrite_csproj(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True
    assert "<Version>2.0.0</Version>" in p.read_text()


def test_dispatch_via_registry_for_csproj(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True


def test_dispatch_for_fsproj(tmp_path: Path):
    """F# projects (.fsproj) use the same MSBuild XML — same
    rewriter applies."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""", name="App.fsproj")
    results = rewrite(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True


def test_versionless_packageref_is_not_found(tmp_path: Path):
    """A csproj with versionless ``<PackageReference Include="X" />``
    (CPM-style) has no version attribute to update — the bumper
    should be targeting the Directory.Packages.props instead, not
    this rewriter. We return not_found cleanly."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""")
    results = rewrite_csproj(p, [RewriteEdit(
        locator="X", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is False
    assert results[0].reason == "not_found"
