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
    """Re-running an already-applied edit is a ``no_change`` no-op
    (every occurrence is already at the new version) — the same
    idempotency contract as the csproj / Directory.Build.targets
    siblings that share the ``apply_version_edit`` driver."""
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
    assert results[0].reason == "no_change"


def test_duplicate_conditional_rows_all_bumped(tmp_path: Path):
    """CPM files legitimately pin the same package in multiple
    conditional ``<ItemGroup Condition=…>`` blocks (per-TFM central
    pins). EVERY occurrence still at the old version must be bumped —
    a last-match rewrite left the other conditional branch on the
    vulnerable version while reporting a clean apply."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup Condition="'$(TargetFramework)' == 'net6.0'">
    <PackageVersion Include="System.Text.Json" Version="6.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'">
    <PackageVersion Include="System.Text.Json" Version="6.0.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="System.Text.Json",
        old_value="6.0.0", new_value="6.0.10",
    )])
    assert results[0].applied is True
    body = p.read_text()
    assert body.count('Version="6.0.10"') == 2
    assert 'Version="6.0.0"' not in body


def test_reversed_attribute_order_twin_bumped(tmp_path: Path):
    """MSBuild is attribute-order-agnostic: ``<PackageVersion
    Version="…" Include="X"/>`` pins exactly like the Include-first
    spelling. An Include-then-Version pattern left the reversed twin
    invisible — it never entered the all-occurrence verdict, so the
    run reported a clean apply (``applied=True`` with an empty
    reason) while the twin stayed on the vulnerable version."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="System.Text.Json" Version="6.0.0" />
    <PackageVersion Version="6.0.0" Include="System.Text.Json" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="System.Text.Json",
        old_value="6.0.0", new_value="6.0.10",
    )])
    assert results[0].applied is True
    assert results[0].reason == ""
    body = p.read_text()
    assert body.count('"6.0.10"') == 2
    assert '"6.0.0"' not in body
    # Attribute order itself is preserved verbatim.
    assert '<PackageVersion Version="6.0.10" Include="System.Text.Json" />' \
        in body


def test_reversed_attribute_order_global_package_reference(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <GlobalPackageReference Version="1.0.0" Include="SourceLink" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="SourceLink", old_value="1.0.0", new_value="1.1.1",
    )])
    assert results[0].applied is True
    assert '<GlobalPackageReference Version="1.1.1" Include="SourceLink" />' \
        in p.read_text()


def test_duplicate_rows_mixed_values_partial_reason(tmp_path: Path):
    """When a third value is present alongside the old one, the
    old-value occurrence is still bumped and the result carries an
    explicit ``partial:`` reason — never a clean apply over a mixed
    file."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="A" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net48'">
    <PackageVersion Include="A" Version="0.9.0" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="A", old_value="1.0.0", new_value="2.0.0",
    )])
    assert results[0].applied is True
    assert results[0].reason.startswith("partial:")
    body = p.read_text()
    assert 'Version="2.0.0"' in body
    assert 'Version="0.9.0"' in body


def test_attr_pattern_repeated_open_tags_without_close_is_fast():
    """A hostile text of repeated ``<PackageVersion `` openers with no
    ``>`` anywhere: the shared attr-pattern builder's unbounded tag
    spans scanned to EOF per anchor — quadratic (measured 4x per size
    doubling). The bounded span keeps each anchor's scan O(1); wall
    bound follows the suite's <5s convention. Scoped to the shared
    builder on purpose — the per-file child-element patterns carry
    the same shape but belong to the escalated trailing-span class."""
    import time

    from packages.sca.rewriters import build_element_attr_version_pattern

    pat = build_element_attr_version_pattern(
        ("PackageVersion", "GlobalPackageReference"),
        "Include", "Newtonsoft.Json", "Version",
    )
    text = "<PackageVersion " * 40000
    start = time.monotonic()
    assert list(pat.finditer(text)) == []
    assert time.monotonic() - start < 5.0


def test_attribute_heavy_open_tag_still_rewrites(tmp_path: Path):
    """Two-direction guard for the 4096-char tag-span bound: a
    legitimately attribute-heavy row (long Condition and padding,
    well under the cap) still matches and bumps."""
    padding = 'Condition=" \'$(TargetFramework)\' == \'net8.0\' "' + " " * 700
    p = _write(tmp_path, f"""\
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" {padding} Version="13.0.1" />
  </ItemGroup>
</Project>
""")
    results = rewrite_directory_packages_props(p, [RewriteEdit(
        locator="Newtonsoft.Json",
        old_value="13.0.1", new_value="13.0.3",
    )])
    assert results[0].applied is True
    assert 'Version="13.0.3"' in p.read_text()
