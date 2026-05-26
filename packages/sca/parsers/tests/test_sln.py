"""Tests for ``packages.sca.parsers.sln``.

Pins:
  * Project-line regex parses the canonical
    ``Project("{GUID}") = "name", "relpath", "{GUID}"`` format.
  * Path traversal defence — absolute paths and ``..``-walks past
    the .sln's grandparent are rejected.
  * Non-MSBuild project types (.sqlproj, solution folders) are
    filtered out.
  * Discovery integration enriches the manifest set with
    out-of-tree csproj referenced from a .sln.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.parsers.sln import find_sln_referenced_csprojs


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Basic shape
# ---------------------------------------------------------------------------

_SLN_BODY = """\
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "AppA", "src/AppA/AppA.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Shared", "src/Shared/Shared.csproj", "{22222222-2222-2222-2222-222222222222}"
EndProject
Global
    GlobalSection(SolutionConfigurationPlatforms) = preSolution
        Debug|Any CPU = Debug|Any CPU
    EndGlobalSection
EndGlobal
"""


def test_extracts_csproj_paths(tmp_path: Path):
    sln = _write(tmp_path / "Solution.sln", _SLN_BODY)
    _write(tmp_path / "src/AppA/AppA.csproj", "<Project />")
    _write(tmp_path / "src/Shared/Shared.csproj", "<Project />")

    found = find_sln_referenced_csprojs(sln)
    assert found == [
        (tmp_path / "src/AppA/AppA.csproj").resolve(),
        (tmp_path / "src/Shared/Shared.csproj").resolve(),
    ]


def test_returns_empty_when_file_missing(tmp_path: Path):
    assert find_sln_referenced_csprojs(tmp_path / "Missing.sln") == []


def test_normalises_windows_separators(tmp_path: Path):
    """Real-world .sln files often use ``\\`` separators (written
    on Windows). The parser must normalise to forward slashes."""
    sln = _write(tmp_path / "Solution.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"AppA", "src\\AppA\\AppA.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n')
    _write(tmp_path / "src/AppA/AppA.csproj", "<Project />")
    found = find_sln_referenced_csprojs(sln)
    assert found == [(tmp_path / "src/AppA/AppA.csproj").resolve()]


def test_filters_non_msbuild_project_types(tmp_path: Path):
    """``.sln`` can reference ``.sqlproj``, ``.shproj``, solution
    folders, etc. SCA's NuGet parser only handles csproj / fsproj
    / vbproj — filter the rest out so we don't try to dispatch
    on a file shape we can't parse."""
    sln = _write(tmp_path / "Solution.sln",
        # csproj — kept
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"App", "App.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
        # sqlproj — filtered
        'Project("{00D1A9C2-B5F0-4AF3-8072-F6C62B433612}") = '
        '"DB", "DB.sqlproj", '
        '"{22222222-2222-2222-2222-222222222222}"\n'
        'EndProject\n'
        # Solution folder — filtered (relpath is the folder name)
        'Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = '
        '"Solution Items", "Solution Items", '
        '"{33333333-3333-3333-3333-333333333333}"\n'
        'EndProject\n')
    _write(tmp_path / "App.csproj", "<Project />")
    _write(tmp_path / "DB.sqlproj", "<Project />")
    found = find_sln_referenced_csprojs(sln)
    assert found == [(tmp_path / "App.csproj").resolve()]


def test_skips_referenced_file_that_does_not_exist(tmp_path: Path):
    """A .sln may reference a project that was deleted but the
    .sln wasn't updated. Silently drop — don't crash, don't emit
    a phantom manifest path."""
    sln = _write(tmp_path / "Solution.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Ghost", "Ghost.csproj", '
        '"{99999999-9999-9999-9999-999999999999}"\n'
        'EndProject\n')
    assert find_sln_referenced_csprojs(sln) == []


def test_rejects_absolute_path_in_sln(tmp_path: Path):
    """A hostile .sln pointing at an absolute path
    (``/etc/passwd``-shape) must be skipped."""
    sln = _write(tmp_path / "Solution.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Evil", "/etc/passwd", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n')
    assert find_sln_referenced_csprojs(sln) == []


def test_rejects_path_traversal_outside_grandparent(tmp_path: Path):
    """A .sln walking ``../../`` to a path outside the .sln's
    grandparent is suspect. One ``..`` (sibling) is fine —
    monorepo .sln files routinely do that — beyond that is
    treated as traversal."""
    outer = tmp_path / "outer"
    outer.mkdir()
    inner = outer / "solutions"
    inner.mkdir()
    sln = _write(inner / "S.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Evil", "../../escape/Evil.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n')
    escape = tmp_path / "escape"
    _write(escape / "Evil.csproj", "<Project />")
    assert find_sln_referenced_csprojs(sln) == []


def test_sibling_via_double_dot_is_accepted(tmp_path: Path):
    """``../Shared/Shared.csproj`` from a sub-solution is
    legitimate monorepo layout — must be accepted."""
    repo = tmp_path
    appa_dir = repo / "src" / "AppA"
    shared_dir = repo / "src" / "Shared"
    sln = _write(appa_dir / "AppA.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Shared", "../Shared/Shared.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n')
    _write(shared_dir / "Shared.csproj", "<Project />")
    found = find_sln_referenced_csprojs(sln)
    assert found == [(shared_dir / "Shared.csproj").resolve()]


def test_deduplicates_repeated_references(tmp_path: Path):
    sln = _write(tmp_path / "S.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"A", "A.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"A-again", "A.csproj", '
        '"{22222222-2222-2222-2222-222222222222}"\n'
        'EndProject\n')
    _write(tmp_path / "A.csproj", "<Project />")
    found = find_sln_referenced_csprojs(sln)
    assert len(found) == 1


# ---------------------------------------------------------------------------
# Discovery integration — find_manifests pulls in out-of-tree csprojs
# ---------------------------------------------------------------------------

def test_discovery_picks_up_sln_referenced_csproj(tmp_path: Path):
    """Monorepo case: ``src/AppA/AppA.sln`` references
    ``src/Shared/Shared.csproj``. Scanning ``tmp_path`` (which IS
    the repo root and contains both) finds AppA via rglob and
    Shared via the .sln walk. Tests the integration path."""
    from packages.sca.discovery import find_manifests

    _write(tmp_path / "src/AppA/AppA.sln",
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"AppA", "AppA.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Shared", "../Shared/Shared.csproj", '
        '"{22222222-2222-2222-2222-222222222222}"\n'
        'EndProject\n')
    _write(tmp_path / "src/AppA/AppA.csproj", "<Project />")
    _write(tmp_path / "src/Shared/Shared.csproj", "<Project />")

    manifests = find_manifests(tmp_path)
    csproj_paths = {
        str(m.path.relative_to(tmp_path)) for m in manifests
        if m.path.suffix == ".csproj"
    }
    assert csproj_paths == {
        "src/AppA/AppA.csproj",
        "src/Shared/Shared.csproj",
    }
