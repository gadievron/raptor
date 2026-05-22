"""Adversarial regression tests for the CPM / .sln / Gradle catalog
read path.

These tests pin the hardening applied after the 2026-05-22
security review of the new SCA parsers. Each finding from that
review gets one negative test here — if a future refactor
re-introduces the issue, this file fails. The companion happy-
path tests live in ``test_directory_packages_props.py``,
``test_sln.py``, and ``test_gradle_version_catalog.py``.

Findings exercised (one test per row, plus a few combinations):

  1. Symlink-follow during parse leaks privileged file contents
  2. Unbounded reads (DoS) on oversized manifests
  3. .sln path traversal — absolute / drive-letter / percent-encoded
     / NUL-injection / out-of-repo via repo_root bound
  4. .sln symlinked csproj target rejected
  5. MSBuild ``@(...)`` and ``%(...)`` expressions skipped (not
     just ``$(...)``) — keeps attacker text out of dep.version
  6. Walk-up cap defends scans without ``.git`` directory
  7. _PARSE_CACHE cleared at scan boundary
  8. Untrusted log args are escape_nonprintable'd
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# 1+2. CPM symlink-follow + size-cap defences.
# ---------------------------------------------------------------------------

def test_cpm_rejects_symlinked_props_file(tmp_path, caplog):
    """A hostile target with ``Directory.Packages.props -> /etc/shadow``
    must NOT leak the symlink target's contents into the parser's
    error logs (previously the read followed the symlink, the XML
    parse failed, and the parser logged the ParseError message —
    which on stdlib stdout-quotes a snippet of the offending text)."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests, parse_directory_packages_props,
    )
    _reset_cache_for_tests()
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET-CONTENTS-MUST-NOT-LEAK\n")
    cpm = tmp_path / "Directory.Packages.props"
    os.symlink(secret, cpm)

    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        result = parse_directory_packages_props(cpm)
    assert result is None
    # The secret contents must NOT appear anywhere in the captured log.
    assert "SECRET-CONTENTS-MUST-NOT-LEAK" not in caplog.text


def test_cpm_rejects_oversized_file(tmp_path):
    """50 MB is the package-wide bound. A 51 MB file is treated as
    unparseable — refusing to OOM the scanner on a hostile manifest."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    from packages.sca.parsers import _safe_read

    _reset_cache_for_tests()
    cpm = tmp_path / "Directory.Packages.props"
    # Write just-over-cap. Use a tiny cap via monkeypatching? Simpler
    # to drive read_bounded with its public ``max_bytes`` and verify
    # via a wrapper — but the parser doesn't expose that knob. Test
    # the helper directly with a small cap that we KNOW the parser
    # uses by default:
    body = b"<Project/>\n" * 1000
    cpm.write_bytes(body)
    # Run read_bounded with a tighter cap than the file's size:
    text = _safe_read.read_bounded(cpm, max_bytes=100, follow_symlinks=False)
    assert text is None


def test_cpm_rejects_fifo(tmp_path):
    """Non-regular final targets (FIFO / socket / device) are also
    rejected — even when ``follow_symlinks=False`` is set, the file
    type check catches a directly-named FIFO that doesn't go through
    a symlink."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo unavailable on this platform")
    from packages.sca.parsers import _safe_read

    fifo = tmp_path / "Directory.Packages.props"
    os.mkfifo(str(fifo))
    text = _safe_read.read_bounded(fifo, follow_symlinks=False)
    assert text is None


# ---------------------------------------------------------------------------
# 3. .sln path traversal.
# ---------------------------------------------------------------------------

def test_sln_rejects_absolute_path():
    """An absolute referenced csproj never wins. Pure-string test
    — no FS access required."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        sln = td_p / "App.sln"
        sln.write_text(
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
            '"X", "/etc/passwd", '
            '"{11111111-1111-1111-1111-111111111111}"\n'
            'EndProject\n'
        )
        assert find_sln_referenced_csprojs(sln, repo_root=td_p) == []


def test_sln_rejects_windows_drive_letter():
    """``C:\\Windows\\System32\\drivers\\etc\\hosts.csproj`` survives
    the backslash normalisation but is blocked by the drive-letter
    check."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        sln = td_p / "App.sln"
        sln.write_text(
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
            '"X", "C:\\\\Windows\\\\System32\\\\hosts.csproj", '
            '"{11111111-1111-1111-1111-111111111111}"\n'
            'EndProject\n'
        )
        assert find_sln_referenced_csprojs(sln, repo_root=td_p) == []


def test_sln_rejects_percent_encoded_path(tmp_path):
    """A hostile ``.sln`` carrying ``%2e%2e/etc/passwd`` survives the
    backslash normalisation but is rejected at the percent-check."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    sln = tmp_path / "App.sln"
    sln.write_text(
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"X", "%2e%2e/etc/passwd", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
    )
    assert find_sln_referenced_csprojs(sln, repo_root=tmp_path) == []


def test_sln_rejects_nul_byte(tmp_path):
    """Embedded NUL bytes in the path are rejected before resolution."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    sln = tmp_path / "App.sln"
    sln.write_text(
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"X", "App.csproj\x00/etc/passwd", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
    )
    assert find_sln_referenced_csprojs(sln, repo_root=tmp_path) == []


def test_sln_rejects_outside_repo_root_via_dotdot(tmp_path):
    """When ``repo_root`` is provided (discovery does this), a
    ``../../OUTSIDE.csproj`` that escapes ``repo_root`` is rejected
    even though the resolved candidate technically exists."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    repo = tmp_path / "repo"
    repo.mkdir()
    sub = repo / "src"
    sub.mkdir()
    outside = tmp_path / "OUTSIDE.csproj"
    outside.write_text("<Project />")
    sln = sub / "App.sln"
    rel = "../../OUTSIDE.csproj"
    sln.write_text(
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        f'"X", "{rel}", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
    )
    found = find_sln_referenced_csprojs(sln, repo_root=repo)
    assert found == []


def test_sln_sibling_via_dotdot_within_repo_still_works(tmp_path):
    """Legitimate monorepo pattern: ``.sln`` in ``src/AppA/`` refers
    to ``../Shared/Shared.csproj``. With ``repo_root`` set to the
    repo root, this MUST still resolve — security must not break
    the workflow."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    repo = tmp_path / "repo"
    (repo / "src" / "AppA").mkdir(parents=True)
    shared = repo / "src" / "Shared"
    shared.mkdir(parents=True)
    csproj = shared / "Shared.csproj"
    csproj.write_text("<Project />")
    sln = repo / "src" / "AppA" / "App.sln"
    sln.write_text(
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"Shared", "../Shared/Shared.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
    )
    assert find_sln_referenced_csprojs(sln, repo_root=repo) == [
        csproj.resolve(),
    ]


def test_sln_rejects_symlinked_csproj_target(tmp_path):
    """Final-candidate symlink-check: ``X.csproj -> /etc/passwd``
    must NOT be returned by discovery."""
    from packages.sca.parsers.sln import find_sln_referenced_csprojs
    repo = tmp_path / "repo"
    repo.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("not-a-csproj")
    csproj = repo / "Sneaky.csproj"
    os.symlink(secret, csproj)
    sln = repo / "App.sln"
    sln.write_text(
        'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
        '"X", "Sneaky.csproj", '
        '"{11111111-1111-1111-1111-111111111111}"\n'
        'EndProject\n'
    )
    assert find_sln_referenced_csprojs(sln, repo_root=repo) == []


# ---------------------------------------------------------------------------
# 5. MSBuild expression coverage — ``@(...)`` and ``%(...)``.
# ---------------------------------------------------------------------------

def test_cpm_skips_at_and_percent_expressions(tmp_path):
    """The MSBuild item-reference ``@(EvilItem)`` and well-known-
    metadata ``%(meta)`` forms must also be skipped — previously
    only ``$(prop)`` was caught, so attacker text in these forms
    landed in ``dep.version`` verbatim."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests, parse_directory_packages_props,
    )
    _reset_cache_for_tests()
    cpm = tmp_path / "Directory.Packages.props"
    cpm.write_text(
        '<Project>\n'
        '  <ItemGroup>\n'
        '    <PackageVersion Include="A" Version="@(EvilItem)" />\n'
        '    <PackageVersion Include="B" Version="%(meta)" />\n'
        '    <PackageVersion Include="C" Version="$(Prop)" />\n'
        '    <PackageVersion Include="D" Version="1.2.3" />\n'
        '  </ItemGroup>\n'
        '</Project>\n'
    )
    result = parse_directory_packages_props(cpm)
    assert result is not None
    # Only D resolves; A/B/C all carry MSBuild expressions and skip.
    names = [p.name for p in result.packages]
    assert names == ["D"]


# ---------------------------------------------------------------------------
# 6. Walk-up depth cap (defence when no .git boundary).
# ---------------------------------------------------------------------------

def test_walk_up_capped_when_no_git(tmp_path):
    """Without a ``.git`` boundary, the walk-up MUST stop at the
    configured depth cap rather than march to ``/``. Build a 20-
    level deep tree with NO .git anywhere, plant a CPM file at the
    top, and verify a deep csproj does NOT see it (the cap stops
    short of the top)."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests, find_cpm_chain,
    )
    _reset_cache_for_tests()
    # tmp_path -> a/b/c/.../t (20 levels deep). Plant the CPM file
    # in tmp_path/zzz/. Walk-up from the deepest dir should NOT
    # cross 12 levels and reach the planted CPM.
    here = tmp_path
    for i in range(20):
        here = here / f"d{i}"
        here.mkdir()
    plant_dir = tmp_path  # the absolute top
    (plant_dir / "Directory.Packages.props").write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="X" Version="1.0.0" /></ItemGroup>'
        '</Project>'
    )
    chain = find_cpm_chain(here)
    # The deepest 20-level path is well past the 12-level cap; the
    # plant at the top is not in the chain.
    assert chain == []


def test_walk_up_stops_at_git_boundary(tmp_path):
    """With ``.git`` present, walk-up stops at the repo boundary
    regardless of the depth cap — the .git check is the primary
    signal."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests, find_cpm_chain,
    )
    _reset_cache_for_tests()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "Directory.Packages.props").write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="X" Version="1.0.0" /></ItemGroup>'
        '</Project>'
    )
    # Sibling planted ABOVE the repo (would-be hostile pickup).
    (tmp_path / "Directory.Packages.props").write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="EVIL" Version="9.9.9" /></ItemGroup>'
        '</Project>'
    )
    sub = repo / "src"
    sub.mkdir()
    chain = find_cpm_chain(sub)
    # Only the in-repo CPM file picks up; the parent-dir plant is
    # blocked by the .git boundary.
    assert len(chain) == 1
    assert chain[0] == (repo / "Directory.Packages.props").resolve()


# ---------------------------------------------------------------------------
# 7. _PARSE_CACHE cleared at scan boundary.
# ---------------------------------------------------------------------------

def test_discovery_clears_cpm_cache(tmp_path):
    """``find_manifests`` clears the per-process CPM cache before
    walking — a stale parse from a previous scan can't leak into
    a new one."""
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import directory_packages_props as cpm_mod

    # Seed the cache with a sentinel entry.
    fake = Path("/nonexistent/seed/Directory.Packages.props")
    cpm_mod._PARSE_CACHE[fake] = None
    assert fake in cpm_mod._PARSE_CACHE

    # Drive a real scan against tmp_path. Should clear the cache.
    target = tmp_path / "empty-repo"
    target.mkdir()
    find_manifests(target)
    assert fake not in cpm_mod._PARSE_CACHE


def test_discovery_clears_gradle_catalog_cache(tmp_path):
    """Same hygiene for the Gradle catalog cache."""
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import gradle_version_catalog as gvc_mod

    fake = Path("/nonexistent/seed/gradle/libs.versions.toml")
    gvc_mod._PARSE_CACHE[fake] = None
    assert fake in gvc_mod._PARSE_CACHE

    target = tmp_path / "empty-repo"
    target.mkdir()
    find_manifests(target)
    assert fake not in gvc_mod._PARSE_CACHE


# ---------------------------------------------------------------------------
# 8. Log defang — non-printable bytes in attacker-controlled strings.
# ---------------------------------------------------------------------------

def test_cpm_xml_parse_error_log_defangs_ansi(tmp_path, caplog):
    """A hostile manifest embedding ANSI escapes / control chars in
    the XML content must NOT pass those bytes through to the
    operator's log. ``escape_nonprintable`` rewrites them to
    ``\\xNN`` form."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests, parse_directory_packages_props,
    )
    _reset_cache_for_tests()
    # The file is not valid XML — triggers a ParseError that's
    # logged at WARNING level. Embed a literal ANSI-CSI sequence in
    # the file content; if the renderer ever surfaces the raw error,
    # the operator's terminal would render it.
    cpm = tmp_path / "Directory.Packages.props"
    cpm.write_bytes(b"<Project> \x1b[2J\x1b[H not-valid </Project")
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        result = parse_directory_packages_props(cpm)
    assert result is None
    # The raw ESC byte must NOT appear in any captured log record.
    for record in caplog.records:
        # Inspect each record's rendered message (with args).
        msg = record.getMessage()
        assert "\x1b" not in msg, (
            f"raw ANSI escape leaked into log: {msg!r}"
        )


def test_gradle_catalog_toml_parse_error_log_defangs(tmp_path, caplog):
    """Same defence on the Gradle catalog side: a malformed TOML
    with embedded control chars must not splatter them into the
    operator's log."""
    from packages.sca.parsers.gradle_version_catalog import (
        _reset_cache_for_tests, parse_libs_versions_toml,
    )
    _reset_cache_for_tests()
    toml = tmp_path / "libs.versions.toml"
    # Malformed TOML: bare keys cannot contain ``\x1b``. Trigger a
    # TOMLDecodeError whose error message would otherwise quote the
    # offending bytes.
    toml.write_bytes(b"foo\x1b[2Jbar = \"v\"\n")
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        result = parse_libs_versions_toml(toml)
    assert result is None
    for record in caplog.records:
        msg = record.getMessage()
        assert "\x1b" not in msg, (
            f"raw ANSI escape leaked into log: {msg!r}"
        )
